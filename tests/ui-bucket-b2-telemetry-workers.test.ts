// Desktop Bucket B — PR B2: one run vocabulary + state-aware hero ([U4]), failure-first worker
// triage + turn timeline rail ([U6]), and trustworthy telemetry: fixed-slot KPI strip, <Num>,
// requests/min sparkline ([U7]).
//
// 1. Pure behavior: mode × lifecycle × phase vocabulary, posture breakdown, hero derivation for
//    every lifecycle, failure-signature grouping, Active-now cap, turn timeline rail, <Num> stress
//    formatting (formatNum + SSR markup), traffic sparkline windows / cap / denied ticks / quiet.
// 2. Playwright (seeded project with Running, Paused, Budget-paused, Awaiting approval, Complete,
//    Failed and Stopped runs) at 1280×720 and 1440×900 in light + dark: unified vocabulary on the
//    project tabs, hero per state with exactly one filled primary (header demoted), KPI strip with
//    no sliced digits, Needs-attention lane above a 6-row Active-now cap, the inspector timeline
//    rail, sparkline SVG + cap line + denied ticks + hover readout, and DOM geometry invariants.
//    Set `KOVO_B2_SHOTS_DIR=<dir>` to capture screenshots.
//
// No production source is read as text: everything is asserted through exported behavior or DOM.
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdirSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { canApproveDiscovery, canReviewScope } from '../src/domain.ts'
import {
  lifecycleBreakdown,
  RUN_LIFECYCLES,
  RUN_PHASES,
  runLifecycleLabel,
  runLifecycleMeta,
  runLifecycleOf,
  runModeMeta,
  runModeOf,
  runPhaseOf,
} from '../src/components/run-state.ts'
import { runStatusLabel } from '../src/components/run/meta.ts'
import {
  ACTIVE_NOW_CAP,
  awaitingApprovalTitle,
  buildAttentionLane,
  buildTrafficSparkline,
  buildTurnTimeline,
  capActiveNow,
  deriveRunHero,
  failureSignature,
  matchesTurnFilter,
  SPARK_QUIET_MS,
  toolOpenByDefault,
  traceWindow,
} from '../src/components/run/model.ts'
import type { Assignment } from '../src/components/run/model.ts'
import { compactNumber, formatNum, Num, numWidthCh } from '../src/components/run/num.tsx'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CI_MULT = process.env.CI ? 2 : 1
const HOOK_TIMEOUT_MS = 120_000 * CI_MULT
const SHOTS_DIR = process.env.KOVO_B2_SHOTS_DIR ?? ''
const NO_RAW = /\b(undefined|null|NaN)\b|1000\.0[kKM]/

// ---------------------------------------------------------------------------
// 1. Pure behavior
// ---------------------------------------------------------------------------

describe('[U4] one run vocabulary: mode × lifecycle × phase', () => {
  it('maps tier × policy onto Passive / Supervised / Autonomous (tier 0 → Offline)', () => {
    assert.equal(runModeOf({ capabilityTier: 1, approvalPolicy: 'auto_review' }), 'passive')
    assert.equal(runModeOf({ capabilityTier: 2, approvalPolicy: 'strict' }), 'passive')
    assert.equal(runModeOf({ capabilityTier: 3, approvalPolicy: 'auto_review' }), 'supervised')
    assert.equal(runModeOf({ capabilityTier: 3, approvalPolicy: 'strict' }), 'supervised')
    assert.equal(runModeOf({ capabilityTier: 3, approvalPolicy: 'yolo' }), 'autonomous')
    assert.equal(runModeOf({ capabilityTier: 0, approvalPolicy: 'yolo' }), 'offline')
    assert.deepEqual(['passive', 'supervised', 'autonomous'].map(m => runModeMeta[m as 'passive'].label), ['Passive', 'Supervised', 'Autonomous'])
    for (const meta of Object.values(runModeMeta)) assert.equal(meta.scanLabel.startsWith(meta.label), true, `${meta.scanLabel} extends ${meta.label}`)
  })

  it('collapses every run status onto six lifecycles with label, tone and icon', () => {
    const expected: Record<string, string> = {
      running: 'running', waiting: 'awaiting_approval', paused: 'paused', budget_paused: 'paused',
      complete: 'complete', failed: 'failed', stopped: 'stopped', queued: 'paused', completed: 'complete', canceled: 'stopped',
    }
    for (const [status, lc] of Object.entries(expected)) assert.equal(runLifecycleOf(status), lc, status)
    assert.deepEqual(RUN_LIFECYCLES.map(lc => runLifecycleMeta[lc].label), ['Running', 'Paused', 'Awaiting approval', 'Complete', 'Failed', 'Stopped'])
    for (const lc of RUN_LIFECYCLES) {
      const m = runLifecycleMeta[lc]
      assert.ok(m.label && m.tone && m.icon && m.dot.startsWith('bg-'), lc)
    }
    // The shared run-line / rail label reads the same vocabulary.
    assert.equal(runStatusLabel('waiting'), 'Awaiting approval')
    assert.equal(runStatusLabel('budget_paused'), 'Paused')
    assert.equal(runLifecycleLabel(undefined), 'Stopped')
    assert.equal(runLifecycleOf('nonsense'), 'stopped')
  })

  it('posture breakdown counts each lifecycle exactly instead of lumping them under "in progress"', () => {
    const runs = [{ status: 'running' }, { status: 'waiting' }, { status: 'paused' }, { status: 'budget_paused' }, { status: 'complete' }]
    assert.equal(lifecycleBreakdown(runs).text, '1 running · 2 paused · 1 awaiting approval · 1 complete')
    assert.equal(lifecycleBreakdown([{ status: 'paused' }, { status: 'waiting' }]).text, '1 paused · 1 awaiting approval')
    assert.equal(lifecycleBreakdown([{ status: 'running' }, { status: 'waiting' }]).text, '1 running · 1 awaiting approval')
    // A terminal run still winding down live work reads as running in a live-only breakdown.
    assert.equal(lifecycleBreakdown([{ status: 'stopped' }], { liveOnly: true }).text, '1 running')
    assert.equal(lifecycleBreakdown([]).text, '')
    assert.equal(lifecycleBreakdown(Array.from({ length: 1_200 }, () => ({ status: 'complete' }))).text, '1,200 complete')
  })

  it('places run and worker phases on one labelled 5-step track', () => {
    assert.deepEqual(RUN_PHASES.map(p => p.label), ['Scope', 'Threat model', 'Investigation', 'Verification', 'Report'])
    const cases: [string, number, string][] = [
      ['consent', 1, 'Scope'], ['discovery', 1, 'Scope'], ['review', 1, 'Scope'], ['threat_model', 2, 'Threat model'],
      ['investigation', 3, 'Investigation'], ['verification', 4, 'Verification'], ['retest', 4, 'Verification'], ['complete', 5, 'Report'],
    ]
    for (const [phase, index, label] of cases) {
      const info = runPhaseOf(phase)
      assert.equal(info.index, index, phase)
      assert.equal(info.total, 5)
      assert.equal(info.ariaLabel, `Phase ${index} of 5: ${label}`)
    }
    assert.equal(runPhaseOf('complete').done, true)
    assert.equal(runPhaseOf(null).index, 1)
  })

  it('discovery consent is approvable exactly while waiting in consent; scope review keeps its own guard', () => {
    assert.equal(canApproveDiscovery('consent', 'waiting'), true)
    for (const status of ['running', 'paused', 'complete', 'failed', 'stopped', 'budget_paused'] as const) assert.equal(canApproveDiscovery('consent', status), false)
    assert.equal(canApproveDiscovery('review', 'waiting'), false)
    // Unchanged server-side scope guard: consent is not a scope-review phase.
    assert.equal(canReviewScope('consent', 'waiting'), false)
    assert.equal(canReviewScope('review', 'waiting'), true)
  })
})

describe('[U4] state-aware run hero', () => {
  const base = {
    phase: 'investigation', roundNo: 2, spentUsd: 4, budgetUsd: 25, spentRequests: 120, budgetRequests: 2_000,
    workers: [] as { status: string; outcome?: string | null }[], endedAt: Date.UTC(2026, 10, 20, 14, 2), fmtWhen: () => 'Nov 20, 14:02',
  }
  const hero = (over: Partial<Parameters<typeof deriveRunHero>[0]> & { status: string }) => deriveRunHero({ ...base, ...over })

  it('running: no filled primary, live summary, quiet inspect link', () => {
    const h = hero({ status: 'running', liveSummary: '2 active workers · IDOR differential', workers: [{ status: 'running' }] })
    assert.equal(h.lifecycle, 'running')
    assert.equal(h.title, 'Running — Investigation')
    assert.equal(h.primary, null)
    assert.equal(h.secondary?.id, 'inspect')
    assert.match(h.detail, /IDOR differential/)
  })

  it('budget paused names which budget stopped the run and offers Raise budget', () => {
    const req = hero({ status: 'budget_paused', spentRequests: 2_000, budgetRequests: 2_000 })
    assert.equal(req.title, 'Paused at request budget — 2,000 / 2,000')
    assert.deepEqual(req.primary, { id: 'raise_budget', label: 'Raise budget' })
    const usd = hero({ status: 'budget_paused', spentUsd: 25, budgetUsd: 25, budgetRequests: 0 })
    assert.equal(usd.title, 'Paused at spend budget — $25.00 / $25.00')
    assert.equal(hero({ status: 'budget_paused' }).title, 'Paused at budget')
  })

  it('paused offers Resume; awaiting approval offers Approve & start', () => {
    const p = hero({ status: 'paused', workers: [{ status: 'paused' }, { status: 'waiting_approval' }] })
    assert.equal(p.title, 'Paused — ready to resume')
    assert.deepEqual(p.primary, { id: 'resume', label: 'Resume' })
    assert.match(p.detail, /2 workers parked/)
    const w = hero({ status: 'waiting', phase: 'consent' })
    assert.equal(w.title, 'Awaiting approval — discovery consent')
    assert.equal(w.title, awaitingApprovalTitle('consent'))
    assert.deepEqual(w.primary, { id: 'approve', label: 'Approve & start' })
    assert.equal(hero({ status: 'waiting', phase: 'review' }).title, 'Awaiting approval — scope review')
  })

  it('failed counts exited workers and offers Show failed workers; stopped/complete carry no primary', () => {
    const f = hero({ status: 'failed', workers: [{ status: 'failed', outcome: 'Worker failed: UpstreamTimeout after 30s waiting for the model endpoint; parked.' }, { status: 'failed' }, { status: 'failed' }, { status: 'complete' }] })
    assert.equal(f.title, 'Failed — 3 workers exited')
    assert.equal(f.detail, 'UpstreamTimeout after 30s waiting for the model endpoint')
    assert.deepEqual(f.primary, { id: 'show_failed', label: 'Show failed workers' })
    assert.equal(hero({ status: 'failed' }).primary, null)
    const s = hero({ status: 'stopped', reportLabel: 'Report v2 (partial) · Nov 20, 14:02' })
    assert.equal(s.title, 'Stopped Nov 20, 14:02')
    assert.equal(s.primary, null)
    const c = hero({ status: 'complete', phase: 'complete', reportLabel: 'Report v3 · Nov 20, 14:02', context: ['Autonomous', '3 hosts'] })
    assert.equal(c.title, 'Complete — finished Nov 20, 14:02')
    assert.equal(c.detail, 'Report v3 · Nov 20, 14:02 · Autonomous · 3 hosts')
    assert.equal(c.primary, null)
  })

  it('never leaks raw null/undefined into hero copy across every status', () => {
    for (const status of ['running', 'waiting', 'paused', 'budget_paused', 'complete', 'failed', 'stopped', 'weird']) {
      const h = hero({ status, reportLabel: null, context: [null, undefined, false, ''], workers: [{ status: 'failed', outcome: null }] })
      assert.doesNotMatch(h.title + ' ' + h.detail, NO_RAW, status)
      assert.ok(!(h.title + h.detail).includes(' ·  ·'), status)
    }
  })
})

function worker(id: string, status: string, over: Partial<Assignment> = {}): Assignment {
  return { id, status, phase: 'investigation', title: `Worker ${id}`, objective: '', outcome: null, sourceOrigins: [], createdAt: Number(id.replace(/\D/g, '')) || 0, turnsUsed: 1, maxTurns: 10, requestsUsed: 1, ...over } as unknown as Assignment
}

describe('[U6] failure-first triage', () => {
  it('folds volatile tokens so identical failures share one signature', () => {
    const a = failureSignature('Worker failed: UpstreamTimeout after 30s waiting for the model endpoint; the step was parked.')
    const b = failureSignature('Worker failed: UpstreamTimeout after 41s waiting for the model endpoint; parked again')
    assert.equal(a, b)
    assert.equal(a, 'UpstreamTimeout after Ns waiting for the model endpoint')
    assert.equal(failureSignature('Upstream returned 503 after 3 retries.'), 'Upstream returned 503 after N retries')
    assert.equal(failureSignature(null), 'Worker exited without a recorded reason')
    assert.ok(failureSignature('x'.repeat(400)).length <= 96)
  })

  it('groups failed workers ×N, lists approvals and stalled workers, each worker once', () => {
    const ws = [
      ...Array.from({ length: 5 }, (_, i) => worker(`f${i}`, 'failed', { outcome: `UpstreamTimeout after ${30 + i}s waiting for the model endpoint; parked.` })),
      worker('g1', 'failed', { outcome: 'Scope guard denied a request outside the approved hosts.' }),
      worker('a1', 'waiting_approval'),
      worker('p1', 'paused'),
      worker('r1', 'running'),
      worker('c1', 'complete'),
    ]
    const live = buildAttentionLane(ws, 'running')
    assert.deepEqual(live.groups.map(g => [g.kind, g.workers.length]), [['failed', 5], ['failed', 1], ['approval', 1], ['stalled', 1]])
    assert.equal(live.ids.size, 8)
    assert.ok(!live.ids.has('r1') && !live.ids.has('c1'))
    // A paused run parks its workers on purpose: they stay in Active now, not "stalled".
    const paused = buildAttentionLane(ws, 'paused')
    assert.deepEqual(paused.groups.map(g => g.kind), ['failed', 'failed', 'approval'])
    // Terminal runs keep only the failures.
    assert.deepEqual(buildAttentionLane(ws, 'complete').groups.map(g => g.kind), ['failed', 'failed'])
    // Scale: 5,000 workers stay fast and grouped.
    const t0 = Date.now()
    const many = Array.from({ length: 5_000 }, (_, i) => worker(`m${i}`, i % 2 ? 'failed' : 'complete', { outcome: `UpstreamTimeout after ${i}s; parked.` }))
    const lane = buildAttentionLane(many, 'running')
    assert.equal(lane.groups.length, 1)
    assert.equal(lane.groups[0]!.workers.length, 2_500)
    assert.ok(Date.now() - t0 < 2_000)
  })

  it('caps Active now at 6 rows behind "Show all"', () => {
    assert.equal(ACTIVE_NOW_CAP, 6)
    const nine = Array.from({ length: 9 }, (_, i) => i)
    assert.deepEqual(capActiveNow(nine, false), { shown: [0, 1, 2, 3, 4, 5], hidden: 3 })
    assert.deepEqual(capActiveNow(nine, true), { shown: nine, hidden: 0 })
    assert.deepEqual(capActiveNow([1, 2], false), { shown: [1, 2], hidden: 0 })
  })

  it('turn timeline: proportional bars, outcome segments, filters, equal ticks without durations', () => {
    const turns = [
      { turn: 1, durationMs: 2_000, tools: [{ id: 'a', status: 'ok' as const, durationMs: 1_500 }, { id: 'b', status: 'ok' as const, durationMs: 500 }] },
      { turn: 2, durationMs: 14_000, tools: [{ id: 'c', status: 'error' as const, durationMs: 13_000 }] },
      { turn: 3, durationMs: 7_000, tools: [{ id: 'd', status: 'finding' as const }] },
      { turn: 4, tools: [] },
    ]
    const tl = buildTurnTimeline(turns)
    assert.equal(tl.proportional, true)
    assert.equal(tl.rows[1]!.width, 1)
    assert.equal(tl.rows[0]!.width, 2 / 14)
    assert.deepEqual(tl.rows[0]!.segments.map(s => s.share), [0.75, 0.25])
    assert.deepEqual(tl.counts, { all: 4, errors: 1, findings: 1, slow: 1 })
    assert.deepEqual(tl.rows.filter(r => matchesTurnFilter(r, 'slow')).map(r => r.turn), [2])
    assert.deepEqual(tl.rows.filter(r => matchesTurnFilter(r, 'errors')).map(r => r.turn), [2])
    assert.ok(tl.rows[3]!.width > 0, 'no-duration turn still draws a tick')
    const flat = buildTurnTimeline([{ turn: 1, tools: [{ id: 'x', status: 'ok' }, { id: 'y', status: 'pending' }] }, { turn: 2, tools: [] }])
    assert.equal(flat.proportional, false)
    assert.deepEqual(flat.rows.map(r => r.width), [1, 1])
    assert.deepEqual(flat.rows[0]!.segments.map(s => s.share), [0.5, 0.5])
    assert.equal(toolOpenByDefault('ok'), false)
    assert.equal(toolOpenByDefault('pending'), false)
    assert.equal(toolOpenByDefault('error'), true)
    assert.equal(toolOpenByDefault('finding'), true)
  })

  it('windows traces past 40 turns and leaves short traces whole', () => {
    assert.deepEqual(traceWindow(40, 0), { start: 0, end: 40, windowed: false })
    const w = traceWindow(150, 0)
    assert.equal(w.windowed, true)
    assert.ok(w.end - w.start <= 40)
    const mid = traceWindow(150, 100)
    assert.ok(mid.start <= 100 && mid.end > 100)
    assert.ok(traceWindow(150, 149).end === 150)
  })
})

describe('[U7] <Num> primitive under stress', () => {
  it('formats grouped and compact values without NaN, null or "1000.0k"', () => {
    assert.equal(formatNum(999_999, 'count').text, '999,999')
    assert.deepEqual(formatNum(999_999, 'count', { compact: true }), { text: '1.0M', exact: '999,999', compacted: true })
    assert.equal(formatNum(999_999, 'usd').text, '$999,999.00')
    assert.deepEqual(formatNum(999_999, 'usd', { compact: true }), { text: '$1.0M', exact: '$999,999.00', compacted: true })
    assert.equal(formatNum(999_999_999, 'tokens').text, '1.0B')
    assert.equal(formatNum(1_000_000_000, 'tokens').text, '1.0B')
    assert.equal(formatNum(999_999_999, 'tokens').exact, '999,999,999 tokens')
    assert.equal(formatNum(10_500, 'count', { compact: true }).text, '10.5k')
    assert.equal(formatNum(9_999, 'count', { compact: true }).text, '9,999')
    assert.equal(formatNum(0.004, 'usd').text, '<$0.01')
    assert.equal(formatNum(0.452, 'pct').text, '45%')
    assert.equal(formatNum(1, 'pct').text, '100%')
    assert.equal(formatNum(12_345, 'ms', { compact: true }).text, '12.3s')
    for (const v of [NaN, Infinity, -Infinity, null, undefined]) {
      for (const kind of ['count', 'usd', 'ms', 'turns', 'pct', 'rel', 'tokens'] as const) assert.equal(formatNum(v as number, kind).text, '—')
    }
    for (let n = 1; n < 2e12; n = n * 3 + 7) {
      for (const kind of ['count', 'usd', 'tokens'] as const) assert.doesNotMatch(formatNum(n, kind, { compact: true }).text, NO_RAW, `${kind} ${n}`)
    }
    assert.equal(compactNumber(999_950), '1.0M')
    assert.equal(compactNumber(-12_345), '-12.3k')
  })

  it('renders tabular, ch-reserved markup with the exact value in the tooltip', () => {
    const html = renderToStaticMarkup(createElement(Num, { value: 999_999, kind: 'count', compact: true }))
    assert.match(html, /tabular-nums/)
    assert.match(html, /title="999,999"/)
    assert.match(html, />1\.0M</)
    assert.match(html, /min-width:4ch/)
    const usd = renderToStaticMarkup(createElement(Num, { value: 999_999, kind: 'usd' }))
    assert.match(usd, />\$999,999\.00</)
    assert.doesNotMatch(usd, /title=/, 'no tooltip when nothing was abbreviated')
    const reserved = renderToStaticMarkup(createElement(Num, { value: 12, kind: 'count', max: 999_999, unit: 'req' }))
    assert.match(reserved, /min-width:7ch/)
    assert.match(reserved, /> req</, 'unit keeps a real space in text content')
    assert.equal(numWidthCh(12, 'count', { max: 999_999 }), 7)
    const tok = renderToStaticMarkup(createElement(Num, { value: 999_999_999, kind: 'tokens' }))
    assert.match(tok, />1\.0B</)
    assert.match(tok, /title="999,999,999 tokens"/)
    assert.doesNotMatch(renderToStaticMarkup(createElement(Num, { value: null })), NO_RAW)
  })
})

describe('[U7] requests/min traffic sparkline', () => {
  const now = Date.UTC(2026, 10, 28, 12, 0)
  const MIN = 60_000

  it('live runs chart the last 60 minutes with a req/min cap line and denied ticks', () => {
    const exchanges = [
      ...Array.from({ length: 40 }, (_, i) => ({ createdAt: now - 5 * MIN + i * 100, status: i % 10 === 0 ? 403 : 200 })),
      { createdAt: now - 30 * MIN, status: 429 },
      { createdAt: now - 30 * MIN + 10, status: 503 },
      { createdAt: now - 3 * 60 * MIN, status: 200 }, // outside the live window
    ]
    const s = buildTrafficSparkline({ status: 'running', createdAt: now - 4 * 60 * MIN, now, maxRpsPerOrigin: 1, exchanges, events: [] })
    assert.equal(s.window, 'live')
    assert.equal(s.buckets.length, 60)
    assert.equal(s.t1, now)
    assert.equal(s.bucketMs, MIN)
    assert.equal(s.capPerMin, 60)
    assert.equal(s.capInScale, true)
    assert.equal(s.peakPerMin, 40)
    assert.equal(s.total, 42)
    assert.equal(s.denied, 6)
    assert.equal(s.buckets[55]!.count, 40)
    assert.equal(s.buckets[55]!.denied, 4)
    assert.equal(s.buckets[30]!.denied, 2)
    assert.equal(s.quiet, false)
    assert.ok(s.yMax >= s.capPerMin)
  })

  it('terminal runs chart the full traffic span (never stretched by late records)', () => {
    const start = now - 6 * 60 * MIN
    const exchanges = Array.from({ length: 30 }, (_, i) => ({ createdAt: start + i * 10 * MIN, status: 200 }))
    const s = buildTrafficSparkline({ status: 'complete', createdAt: start, now, maxRpsPerOrigin: 20, exchanges, events: [] })
    assert.equal(s.window, 'full')
    assert.equal(s.t0, start)
    assert.ok(s.t1 >= start + 290 * MIN && s.t1 <= start + 300 * MIN, `ends at last traffic, got ${(s.t1 - start) / MIN} min`)
    assert.ok(s.buckets.length <= 60)
    assert.equal(s.buckets.reduce((a, b) => a + b.count, 0), 30)
    assert.equal(s.capInScale, false, 'a 1,200/min cap is labelled off-scale next to ~0.1/min traffic')
    assert.equal(s.quiet, false)
    const forced = buildTrafficSparkline({ status: 'running', createdAt: start, now, maxRpsPerOrigin: 20, exchanges, events: [], window: 'full' })
    assert.equal(forced.window, 'full')
  })

  it('prefers broker events, flags quiet live runs, and has a clean empty state', () => {
    const events = [
      { kind: 'broker.allowed', createdAt: now - 20 * MIN },
      { kind: 'broker.allowed', createdAt: now - 20 * MIN + 1 },
      { kind: 'broker.denied', createdAt: now - 19 * MIN },
      { kind: 'worker.complete', createdAt: now },
    ]
    const s = buildTrafficSparkline({ status: 'paused', createdAt: now - 90 * MIN, now, maxRpsPerOrigin: 5, exchanges: [{ createdAt: now - 40 * MIN, status: 200 }], events })
    assert.equal(s.total, 2, 'event stream wins over the loaded exchange window')
    assert.equal(s.denied, 1)
    assert.equal(s.quiet, true, 'no traffic in the last 10 minutes of a live run')
    assert.equal(s.lastAt, now - 19 * MIN)
    assert.ok(now - (s.lastAt ?? 0) > SPARK_QUIET_MS)
    const empty = buildTrafficSparkline({ status: 'running', createdAt: now - MIN, now, maxRpsPerOrigin: 5, exchanges: [], events: [] })
    assert.equal(empty.empty, true)
    assert.equal(empty.quiet, false)
    assert.equal(empty.peakPerMin, 0)
    assert.ok(empty.buckets.every(b => b.perMin === 0))
    const junk = buildTrafficSparkline({ status: 'complete', createdAt: NaN, now, maxRpsPerOrigin: 0, exchanges: [{ createdAt: NaN, status: 200 }], events: [{ kind: 'broker.allowed', createdAt: Infinity }] })
    assert.equal(junk.empty, true)
    assert.ok(junk.buckets.length >= 1 && Number.isFinite(junk.t0) && Number.isFinite(junk.t1))
  })
})

// ---------------------------------------------------------------------------
// 2. Playwright
// ---------------------------------------------------------------------------

const SYSTEM_CHROMIUM = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') { pw = loaded as PlaywrightModule; break }
    } catch {
      // try next package
    }
  }
  if (!pw) return null
  let bundled = ''
  try { bundled = pw.chromium.executablePath() } catch { bundled = '' }
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  const sys = SYSTEM_CHROMIUM.find(p => existsSync(p))
  return sys ? { pw, executablePath: sys } : null
}

async function freePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate a port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function ensureBuilt(): void {
  if (existsSync(resolve(REPO_ROOT, 'build/server/server.js')) && existsSync(resolve(REPO_ROOT, 'build/client'))) return
  execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'pipe' })
}

interface Kovo { origin: string; dataDir: string; bootstrapSecret: string; stop(): Promise<void> }

async function startKovo(): Promise<Kovo> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-b2-telemetry-'))
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: REPO_ROOT,
    env: { ...process.env, PORT: String(port), KOVO_DATA_DIR: dataDir, KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1', KOVO_OFFLINE: '', KOVO_PUBLIC_ORIGIN: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', c => { output += String(c) })
  child.stderr?.on('data', c => { output += String(c) })
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])
      if (timedOut && child.exitCode === null) { child.kill('SIGKILL'); await once(child, 'exit') }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  let healthy = false
  for (let i = 0; i < 200 && child.exitCode === null; i += 1) {
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(500) })
      if (res.ok) { healthy = true; break }
    } catch {
      // not bound yet
    }
    await delay(70)
  }
  if (!healthy) { await stop(); throw new Error(`serve.ts failed to start.\n${output.slice(-2_000)}`) }
  let bootstrapSecret = ''
  for (let i = 0; i < 40 && !bootstrapSecret; i += 1) {
    try { bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
  }
  if (!bootstrapSecret) { await stop(); throw new Error('bootstrap secret missing') }
  return { origin, dataDir, bootstrapSecret, stop }
}

function withDb<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try { db.exec('PRAGMA busy_timeout = 5000;'); return fn(db) } finally { db.close() }
}

/** Clone a run row under a new id (every column copied, then overridden). */
function cloneRun(db: DatabaseSync, fromId: string, toId: string, set: Record<string, string | number>): void {
  const cols = (db.prepare('PRAGMA table_info(runs)').all() as Array<{ name: string }>).map(c => c.name)
  const select = cols.map(c => (c === 'id' ? '?' : c)).join(', ')
  db.prepare(`INSERT INTO runs (${cols.join(', ')}) SELECT ${select} FROM runs WHERE id = ?`).run(toId, fromId)
  const keys = Object.keys(set)
  if (keys.length) db.prepare(`UPDATE runs SET ${keys.map(k => `${k} = ?`).join(', ')} WHERE id = ?`).run(...keys.map(k => set[k]!), toId)
}

const ORIGINS = ['https://app.acme-cloud.example', 'https://api.acme-cloud.example', 'https://admin.acme-cloud.example']
const MIN = 60_000
const UPSTREAM = (i: number) => `Worker failed: UpstreamTimeout after ${30 + i}s waiting for the model endpoint; the step was parked for retry.`

interface Seeded {
  project: string
  running: string
  paused: string
  budget: string
  waiting: string
  complete: string
  failed: string
  stopped: string
  traceWorker: string
}

/** Durable worker session (50 turns) for the inspector's turn timeline rail. */
function seedSession(dataDir: string, sessionId: string, t0: number): void {
  const dir = join(dataDir, 'agent-sessions')
  mkdirSync(dir, { recursive: true })
  const db = new DatabaseSync(join(dir, `${sessionId}.sqlite`))
  try {
    db.exec('CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, commit_seq INTEGER NOT NULL, record TEXT NOT NULL)')
    const ins = db.prepare('INSERT INTO entries (commit_seq, record) VALUES (?, ?)')
    for (let turn = 1; turn <= 50; turn += 1) {
      const error = turn % 9 === 7
      const finding = turn === 12 || turn === 40
      const slow = turn === 5 || turn === 22 || turn === 41
      const durationMs = slow ? 14_000 : 1_200 + (turn % 5) * 400
      const tools = [
        { id: `t${turn}a`, name: 'http_request', ok: !error, ms: Math.round(durationMs * 0.6) },
        ...(finding ? [{ id: `t${turn}f`, name: 'propose_chain_finding', ok: true, ms: 300 }] : [{ id: `t${turn}b`, name: 'record_fact', ok: true, ms: 120 }]),
      ]
      const model = [
        {
          role: 'assistant', timestamp: t0 + turn * 20_000, durationMs,
          content: [
            { type: 'text', text: `Turn ${turn}: compare the control vs. variant response for the invoice listing differential probe.` },
            ...tools.map(tc => ({ type: 'toolCall', id: tc.id, name: tc.name, arguments: tc.name === 'http_request' ? { method: 'GET', origin: ORIGINS[1], pathAndQuery: `/api/v2/invoices?page=${turn}` } : { title: `Benign canary verification ${turn}`, severity: 'low' } })),
          ],
        },
        ...tools.map(tc => ({
          role: 'toolResult', toolCallId: tc.id, isError: !tc.ok, durationMs: tc.ms,
          content: tc.ok ? `200 OK · ${tc.name} recorded` : 'UpstreamTimeout: model endpoint did not answer within 30 s',
        })),
      ]
      ins.run(turn, JSON.stringify({ model }))
    }
  } finally {
    db.close()
  }
}

function seedRuns(dataDir: string, runId: string): Seeded {
  const now = Date.now()
  const candidates = ORIGINS.map((origin, i) => ({ id: `cand-${i + 1}`, origin, source: 'Project seed', thirdParty: false }))
  const approved = JSON.stringify(candidates.map(c => c.id))
  const id = (tag: string) => `${runId.slice(0, 24)}${tag.padEnd(12, '0').slice(0, 12)}`
  const s: Seeded = {
    project: '', running: runId, paused: id('b2a1'), budget: id('b2b1'), waiting: id('b2c1'),
    complete: id('b2d1'), failed: id('b2e1'), stopped: id('b2f1'), traceWorker: 'b2b2b2b2-0000-4000-8000-00000000ace1',
  }
  return withDb(dataDir, db => {
    const meta = db.prepare('SELECT workspace_id, project_id, goal_revision FROM runs WHERE id = ?').get(runId) as { workspace_id: string; project_id: string; goal_revision: number }
    s.project = meta.project_id
    const goalRev = meta.goal_revision
    db.prepare(
      `UPDATE runs SET phase = 'threat_model', status = 'running', capability_tier = 3, approval_policy = 'auto_review', scope_revision = 1,
         candidates = ?, approved = ?, spent_requests = 1240, budget_requests = 5000, spent_usd = 3.2, budget_usd = 25, spent_tokens = 120000,
         turns_used = 140, max_rps_per_origin = 1, created_at = ?, goal = ? WHERE id = ?`,
    ).run(JSON.stringify(candidates), approved, now - 2 * 60 * MIN, 'Verify tenant isolation on the billing API with control vs. variant differential probes', runId)
    db.prepare('DELETE FROM assignments WHERE run_id = ?').run(runId)

    const common = { candidates: JSON.stringify(candidates), approved, scope_revision: 1 }
    cloneRun(db, runId, s.paused, {
      ...common, status: 'paused', phase: 'investigation', capability_tier: 2, approval_policy: 'auto_review', spent_requests: 999_999, budget_requests: 1_000_000,
      spent_usd: 999_999, budget_usd: 1_000_000, spent_tokens: 999_999_999, turns_used: 999_999, created_at: now - 3 * 60 * MIN,
      goal: 'Stress triage: grouped failures, approvals and a long worker trace',
    })
    cloneRun(db, runId, s.budget, { ...common, status: 'budget_paused', phase: 'investigation', capability_tier: 2, spent_requests: 2_000, budget_requests: 2_000, spent_usd: 4.1, goal: 'Budget-capped read-only sweep' })
    cloneRun(db, runId, s.waiting, { status: 'waiting', phase: 'consent', scope_revision: 0, approved: '[]', capability_tier: 1, spent_requests: 0, spent_usd: 0, spent_tokens: 0, turns_used: 0, goal: 'Fresh discovery awaiting consent' })
    cloneRun(db, runId, s.complete, { ...common, status: 'complete', phase: 'complete', capability_tier: 3, approval_policy: 'yolo', created_at: now - 8 * 60 * MIN, goal: 'Nightly autonomous regression' })
    cloneRun(db, runId, s.failed, { ...common, status: 'failed', phase: 'verification', capability_tier: 2, goal: 'Replay verification that exited on upstream timeouts' })
    cloneRun(db, runId, s.stopped, { ...common, status: 'stopped', phase: 'investigation', capability_tier: 1, goal: 'Operator-stopped investigation' })

    const insW = db.prepare(
      `INSERT INTO assignments (id, run_id, asset_id, step_id, input_assignment_id, phase, status, scope_revision, goal_revision,
         session_id, attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins, title, objective, outcome, created_at)
       VALUES (?, ?, ?, NULL, NULL, ?, ?, 1, ?, ?, 0, ?, ?, ?, '[]', ?, ?, ?, ?, ?)`,
    )
    const w = (run: string, wid: string, phase: string, status: string, opts: { req?: number; turns?: number; title?: string; outcome?: string | null; at?: number; session?: string } = {}) =>
      insW.run(wid, run, 'cand-2', phase, status, goalRev, opts.session ?? `s-${wid}`, 150, opts.turns ?? 12, opts.req ?? 40,
        JSON.stringify([ORIGINS[1]]), opts.title ?? `${phase.replace('_', ' ')} differential check ${wid}`, 'Control vs. variant comparison on the approved surface.', opts.outcome ?? null, opts.at ?? now - 60 * MIN)
    // Paused triage run: 9 active, 5 identical failures + 2 others, 1 approval, 6 complete (one with a durable trace).
    const live = ['running', 'running', 'running', 'running', 'running', 'paused', 'paused', 'paused', 'paused']
    live.forEach((st, i) => w(s.paused, `w-act-${i}`, i % 2 ? 'investigation' : 'verification', st, { req: i < 2 ? 999_999 : 30 + i, turns: i < 2 ? 149 : 9, at: now - 50 * MIN + i * 1_000 }))
    for (let i = 0; i < 5; i += 1) w(s.paused, `w-fail-${i}`, 'investigation', 'failed', { outcome: UPSTREAM(i), at: now - 70 * MIN + i * 1_000 })
    for (let i = 0; i < 2; i += 1) w(s.paused, `w-guard-${i}`, 'verification', 'failed', { outcome: 'Worker failed: scope guard denied a request outside the approved hosts.', at: now - 65 * MIN + i * 1_000 })
    w(s.paused, 'w-approval', 'verification', 'waiting_approval', { title: 'State-changing replay awaiting operator approval', at: now - 45 * MIN })
    for (let i = 0; i < 5; i += 1) w(s.paused, `w-done-${i}`, 'threat_model', 'complete', { req: i === 0 ? 999_999 : 20 + i, outcome: 'No issue found.', at: now - 120 * MIN + i * 1_000 })
    w(s.paused, s.traceWorker, 'investigation', 'complete', { title: 'Invoice listing differential probe with a long durable trace', turns: 50, session: 's-trace', outcome: 'Recorded 2 findings.', at: now - 110 * MIN })
    // Failed run: 3 workers that exited on the same signature.
    for (let i = 0; i < 3; i += 1) w(s.failed, `w-ff-${i}`, 'verification', 'failed', { outcome: UPSTREAM(i), at: now - 30 * MIN + i * 1_000 })
    w(s.failed, 'w-ff-done', 'investigation', 'complete', { outcome: 'No issue found.' })

    const insX = db.prepare(
      `INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query,
         persona_handle, status, media_type, req_headers, resp_headers, body_preview, body_artifact_id, body_sha256, secret_matches, duration_ms, created_at)
       VALUES (?, ?, ?, 1, ?, ?, '[]', 'GET', ?, NULL, ?, 'application/json', '{}', '{}', '{"ok":true}', NULL, ?, '[]', 120, ?)`,
    )
    // Every exchange belongs to a worker: one quiet completed worker per traffic-bearing run.
    const owner: Record<string, string> = { [s.running]: 'w-run-done', [s.paused]: 'w-done-1', [s.complete]: 'w-cmp-done', [s.budget]: 'w-bud-done' }
    w(s.running, 'w-run-done', 'investigation', 'complete', { outcome: 'No issue found.', at: now - 100 * MIN })
    w(s.budget, 'w-bud-done', 'investigation', 'complete', { outcome: 'No issue found.', at: now - 100 * MIN })
    // A live worker keeps the server's run loop from closing the seeded running run.
    w(s.running, 'w-run-live', 'threat_model', 'running', { title: 'Surface ranking for the approved billing hosts', at: now - 4 * MIN })
    w(s.complete, 'w-cmp-done', 'investigation', 'complete', { outcome: 'No issue found.', at: now - 7 * 60 * MIN })
    let xi = 0
    const x = (run: string, status: number, at: number) => { xi += 1; insX.run(`x-b2-${xi}`, run, owner[run]!, ORIGINS[xi % 3], ORIGINS[xi % 3], `/api/v2/invoices?page=${xi}`, status, `sha256-${xi}`, at) }
    // Budget-paused (live, never executed by the server loop): a 40-request burst five minutes ago
    // (cap 60/min stays in scale), background traffic and denied ticks for the live 60-minute window.
    for (const run of [s.budget, s.running]) {
      for (let i = 0; i < 40; i += 1) x(run, i % 8 === 0 ? 403 : 200, now - 5 * MIN + i * 150)
      for (let i = 0; i < 30; i += 1) x(run, i % 7 === 3 ? 429 : i % 11 === 5 ? 503 : 200, now - 55 * MIN + i * 90_000)
    }
    // Paused: all traffic older than 10 minutes → "No traffic in the last 10 min".
    for (let i = 0; i < 24; i += 1) x(s.paused, i % 6 === 0 ? 403 : 200, now - 50 * MIN + i * 60_000)
    // Complete: traffic across the whole run (full-run window).
    for (let i = 0; i < 48; i += 1) x(s.complete, i % 9 === 0 ? 500 : 200, now - 8 * 60 * MIN + i * 8 * MIN)
    seedSession(dataDir, 's-trace', now - 110 * MIN)
    return s
  })
}

/**
 * The live server loop eventually closes a seeded running run that has no real worker session;
 * re-pin the fixture (run + its live worker) right before each page that needs the running state.
 */
function pinRunning(dataDir: string, runId: string): void {
  withDb(dataDir, db => {
    db.prepare("UPDATE runs SET status = 'running', phase = 'threat_model' WHERE id = ?").run(runId)
    db.prepare("UPDATE assignments SET status = 'running', outcome = NULL WHERE run_id = ? AND id = 'w-run-live'").run(runId)
    db.prepare("DELETE FROM reports WHERE run_id = ?").run(runId)
  })
}

type Theme = 'light' | 'dark'
interface Combo { width: number; height: number; theme: Theme }
const COMBOS: Combo[] = [
  { width: 1280, height: 720, theme: 'light' },
  { width: 1280, height: 720, theme: 'dark' },
  { width: 1440, height: 900, theme: 'light' },
  { width: 1440, height: 900, theme: 'dark' },
]
const comboName = (c: Combo) => `${c.width}x${c.height}__${c.theme}`

/** Geometry offenders: horizontal overflow, clipped buttons/cards (empty list = clean). */
async function geometryOffenders(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = []
    const visible = (el: Element) => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 }
    const label = (el: Element) => el.tagName.toLowerCase() + (el.getAttribute('aria-label') ? `[${el.getAttribute('aria-label')}]` : '') + (el.getAttribute('data-testid') ? `#${el.getAttribute('data-testid')}` : '')
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth + 1) out.push(`document ${doc.scrollWidth}>${doc.clientWidth}`)
    const containers = document.querySelectorAll('main, aside[aria-label="Inspector"], aside[aria-label="Inspector"] .overflow-auto, main [role="region"], main .overflow-auto, main section, [role="dialog"]')
    for (const el of containers) {
      if (!visible(el)) continue
      if (el.scrollWidth > el.clientWidth + 1) out.push(`${label(el)} scrollWidth ${el.scrollWidth}>${el.clientWidth}`)
    }
    for (const b of document.querySelectorAll<HTMLElement>('main button, aside button, header button, [data-testid="run-hero"], [data-attention-row]')) {
      if (!visible(b) || getComputedStyle(b).overflow === 'visible') continue
      if (b.scrollHeight > b.clientHeight + 2) out.push(`clipped vertically "${(b.textContent ?? '').trim().slice(0, 40)}" ${b.scrollHeight}>${b.clientHeight}`)
    }
    return out
  })
}

/** Filled (accent background) buttons/links inside main. */
async function filledPrimaries(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const probe = document.createElement('span')
    probe.className = 'bg-accent'
    document.body.appendChild(probe)
    const accent = getComputedStyle(probe).backgroundColor
    probe.remove()
    return [...document.querySelectorAll<HTMLElement>('main button, main a')].filter(el => {
      const r = el.getBoundingClientRect()
      return r.width > 0 && r.height > 0 && getComputedStyle(el).backgroundColor === accent
    }).map(el => (el.textContent ?? '').trim())
  })
}

async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    try { await document.fonts?.ready } catch { /* offline */ }
    await new Promise<void>(r => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  })
  await delay(300)
}

async function waitHydrated(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    if (document.readyState !== 'complete') return false
    const el = document.querySelector('main button, nav button')
    return !!el && Object.keys(el).some(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'))
  }, undefined, { timeout: 20_000 * CI_MULT })
}

async function shot(page: Page, name: string, combo: Combo): Promise<void> {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  await page.screenshot({ path: join(SHOTS_DIR, `${name}__${comboName(combo)}.png`) })
}

describe('Bucket B2 rendered behavior and geometry (Playwright)', () => {
  let skip: string | null = null
  let kovo: Kovo | undefined
  let browser: Browser | undefined
  let storageState: Awaited<ReturnType<BrowserContext['storageState']>> | undefined
  let seeded: Seeded | undefined
  const pageErrors: string[] = []

  before(async () => {
    const env = await loadPlaywright()
    if (!env) { skip = 'Playwright or Chromium unavailable'; return }
    ensureBuilt()
    kovo = await startKovo()
    browser = await env.pw.chromium.launch({ headless: true, executablePath: env.executablePath, args: ['--no-sandbox'] })
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 } })
    const page = await ctx.newPage()
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, { waitUntil: 'load' })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 20_000 * CI_MULT })
    await waitHydrated(page).catch(() => undefined)
    await page.getByLabel('Project name').fill('B2 telemetry triage')
    await page.getByLabel('Sites').fill(ORIGINS.join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 20_000 * CI_MULT })
    await page.getByRole('button', { name: 'New run', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor({ state: 'visible' })
    await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
    await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 20_000 * CI_MULT })
    const runId = /\/runs\/([a-f0-9-]+)/.exec(page.url())?.[1]
    assert.ok(runId)
    await delay(500)
    seeded = seedRuns(kovo.dataDir, runId)
    storageState = await ctx.storageState()
    await ctx.close()
  }, { timeout: HOOK_TIMEOUT_MS })

  after(async () => {
    await browser?.close().catch(() => undefined)
    await kovo?.stop().catch(() => undefined)
  })

  async function open(combo: Combo, path: string): Promise<{ page: Page; ctx: BrowserContext }> {
    if (seeded && path.startsWith(`/runs/${seeded.running}`)) pinRunning(kovo!.dataDir, seeded.running)
    const ctx = await browser!.newContext({ viewport: { width: combo.width, height: combo.height }, colorScheme: combo.theme, storageState })
    await ctx.addInitScript({ content: 'globalThis.__name = globalThis.__name || (f => f)' })
    await ctx.addInitScript((theme: string) => { try { localStorage.setItem('kovo-appearance', theme) } catch { /* noop */ } }, combo.theme)
    const page = await ctx.newPage()
    page.setDefaultTimeout(20_000 * CI_MULT)
    page.on('pageerror', err => { pageErrors.push(`${path}: ${err instanceof Error ? err.message : String(err)}`) })
    await page.goto(`${kovo!.origin}${path}`, { waitUntil: 'load' })
    await page.locator('main').first().waitFor({ state: 'attached' })
    await waitHydrated(page)
    await settle(page)
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), combo.theme)
    return { page, ctx }
  }

  /**
   * Open a page that needs the seeded running run: the server's executor may close that fixture at
   * any wake, so re-pin it and reload (bounded) until the page renders the running state.
   */
  async function openRunning(combo: Combo, path: string, ready: (page: Page) => Promise<boolean>): Promise<{ page: Page; ctx: BrowserContext }> {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      pinRunning(kovo!.dataDir, seeded!.running)
      const r = await open(combo, path)
      if (await ready(r.page)) return r
      await r.ctx.close()
    }
    throw new Error(`running fixture did not stay running for ${path}`)
  }

  const L = COMBOS[0]!
  const XL = COMBOS[2]!

  it('[U4] project overview + runs tabs speak one mode/lifecycle vocabulary', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const { page, ctx } = await openRunning(combo, `/projects/${seeded.project}`, async p => /running/.test(await p.locator('[data-slot=posture-title]').innerText()))
      try {
        assert.equal(await page.locator('[data-slot=posture-title]').innerText(), '1 running · 2 paused · 1 awaiting approval', comboName(combo))
        const meta = (await page.locator('[data-slot=overview-run-meta]').allInnerTexts()).join('\n')
        assert.match(meta, /\b(Passive|Supervised|Autonomous) · /)
        assert.doesNotMatch(meta, /Authenticated Testing|Read-Only Scan|Active Testing/)
        assert.equal((await filledPrimaries(page)).length, 1, `${comboName(combo)}: one filled primary on the project overview`)
        assert.deepEqual(await geometryOffenders(page), [], comboName(combo))
      } finally {
        await ctx.close()
      }
      const runs = await openRunning(combo, `/projects/${seeded.project}?tab=runs`, async p => (await p.locator('[data-slot=badge][data-lifecycle=running]').count()) === 1)
      try {
        const page = runs.page
        const section = page.locator('section[aria-label="Project runs"]')
        await section.waitFor()
        assert.equal(await section.locator('[data-slot=runs-lifecycle-breakdown]').innerText(), '· 1 running · 2 paused · 1 awaiting approval · 1 complete · 1 failed · 1 stopped')
        const badges = await section.locator('[data-slot=badge][data-lifecycle]').allInnerTexts()
        assert.deepEqual([...new Set(badges.map(b => b.trim()))].sort(), ['Awaiting approval', 'Complete', 'Failed', 'Paused', 'Running', 'Stopped'])
        // Mode badge: canonical short label, long form (scanModeBadgeInfo) in the tooltip — parity with runModeMeta.
        const modes = await section.locator('[data-slot=badge]:not([data-lifecycle])').evaluateAll(els => els.map(el => [el.textContent?.trim() ?? '', el.getAttribute('title') ?? '']))
        assert.ok(modes.length >= 7)
        for (const [label, title] of modes) {
          const meta = Object.values(runModeMeta).find(m => m.label === label)
          assert.ok(meta, `mode badge "${label}" is a canonical mode`)
          assert.equal(title, meta.scanLabel)
        }
        const runningChip = section.getByRole('button', { name: /^Running/ })
        assert.equal(await runningChip.getAttribute('title'), '1 running · 2 paused · 1 awaiting approval')
        assert.deepEqual(await geometryOffenders(page), [], comboName(combo))
        await shot(page, 'project-runs', combo)
      } finally {
        await runs.ctx.close()
      }
    }
  })

  const HERO_CASES = (s: Seeded) => [
    { name: 'overview-running', path: `/runs/${s.running}?view=overview`, lifecycle: 'running', title: /^Running — Threat model$/, primary: null },
    { name: 'overview-paused', path: `/runs/${s.paused}?view=overview`, lifecycle: 'paused', title: /^Paused — ready to resume$/, primary: 'Resume' },
    { name: 'overview-paused-budget', path: `/runs/${s.budget}?view=overview`, lifecycle: 'paused', title: /^Paused at request budget — 2,000 \/ 2,000$/, primary: 'Raise budget' },
    { name: 'overview-failed', path: `/runs/${s.failed}?view=overview`, lifecycle: 'failed', title: /^Failed — 3 workers exited$/, primary: 'Show failed workers' },
    { name: 'overview-complete', path: `/runs/${s.complete}?view=overview`, lifecycle: 'complete', title: /^Complete — finished /, primary: null },
    { name: 'overview-stopped', path: `/runs/${s.stopped}?view=overview`, lifecycle: 'stopped', title: /^Stopped /, primary: null },
  ]

  it('[U4] state-aware hero per lifecycle with exactly one filled primary (header demoted)', { timeout: 240_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      for (const c of HERO_CASES(seeded)) {
        const { page, ctx }: { page: Page; ctx: BrowserContext } = c.lifecycle === 'running'
          ? await openRunning(combo, c.path, async p => (await p.getByTestId('run-hero').getAttribute('data-lifecycle')) === 'running')
          : await open(combo, c.path)
        const where: string = `${c.name} @ ${comboName(combo)}`
        try {
          const hero: Locator = page.getByTestId('run-hero')
          await hero.waitFor()
          assert.equal(await hero.getAttribute('data-lifecycle'), c.lifecycle, where)
          assert.match(await hero.locator('[data-slot=hero-title]').innerText(), c.title, where)
          const mainText = await page.locator('main').innerText()
          assert.doesNotMatch(mainText, /Provisional summary|As of /, `${where}: no stale provisional eyebrow`)
          assert.equal(await page.getByTestId('budget-paused-banner').count(), 0, `${where}: hero replaces the budget banner on Overview`)
          const filled = await filledPrimaries(page)
          if (c.primary) {
            assert.deepEqual(filled, [c.primary], `${where}: the hero CTA is the only filled primary`)
            const box = await page.locator('[data-hero-primary]').boundingBox()
            assert.ok(box && box.y + box.height <= combo.height && box.x + box.width <= combo.width, `${where}: primary CTA above the fold`)
          } else {
            assert.deepEqual(filled, [], `${where}: no filled primary when nothing is actionable`)
          }
          if (c.primary === 'Resume' || c.primary === 'Raise budget') {
            const header: Locator = page.locator('[data-testid=run-header-actions]').getByRole('button', { name: c.primary })
            assert.equal(await header.getAttribute('data-hero-demoted'), 'true', `${where}: header copy demoted`)
            const hb = await header.boundingBox()
            assert.ok(hb && hb.x + hb.width <= combo.width + 0.5, `${where}: header action stays in viewport`)
          }
          assert.doesNotMatch(await hero.innerText(), NO_RAW, where)
          assert.deepEqual(await geometryOffenders(page), [], where)
          await shot(page, c.name, combo)
        } finally {
          await ctx.close()
        }
      }
    }
  })

  it('[U4] consent: labelled stepper above the scope card, Approve & start enabled and above the fold', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const { page, ctx } = await open(combo, `/runs/${seeded.waiting}?view=overview`)
      const where = comboName(combo)
      try {
        const stepper = page.getByTestId('consent-stepper')
        await stepper.waitFor()
        assert.equal(await stepper.getAttribute('aria-label'), 'Phase 1 of 5: Scope')
        assert.equal(await page.locator('[aria-current="step"]').count(), 1)
        const grid = page.getByTestId('scope-controls-grid')
        if (await grid.count()) {
          const [sb, gb] = [await stepper.boundingBox(), await grid.boundingBox()]
          assert.ok(sb && gb && sb.y < gb.y, `${where}: stepper sits above the scope card`)
        }
        assert.match(await page.locator('main').innerText(), /Awaiting approval — discovery consent/)
        const approve = page.getByTestId('consent-approve')
        assert.equal(await approve.isDisabled(), false, `${where}: consent + waiting can be approved`)
        const box = await approve.boundingBox()
        assert.ok(box && box.y + box.height <= combo.height + 1 && box.x + box.width <= combo.width + 1, `${where}: Approve & start above the fold`)
        const filled = await filledPrimaries(page)
        assert.equal(filled.length, 1, `${where}: one filled primary (${filled.join(' | ')})`)
        assert.ok(filled[0]!.startsWith('Approve & start'), filled[0])
        assert.deepEqual(await geometryOffenders(page), [], where)
        await shot(page, 'overview-waiting-consent', combo)
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U4] failed hero "Show failed workers" opens the failed filter with a failed worker selected', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(XL, `/runs/${seeded.failed}?view=overview`)
    try {
      await page.locator('[data-hero-primary]').click()
      await page.waitForURL(/view=workflow/)
      await page.waitForURL(/sel=worker%3Aw-ff-|sel=worker:w-ff-/)
      await page.getByRole('region', { name: 'Worker list' }).waitFor()
      const pressed = await page.locator('[role=tab][aria-selected=true], [role=tab][aria-pressed=true]').allInnerTexts()
      assert.ok(pressed.some(x => /Failed/.test(x)), `failed filter active: ${pressed.join('|')}`)
    } finally {
      await ctx.close()
    }
  })

  it('[U7] fixed-slot KPI strip never slices digits; <Num> stress values render exactly', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const { page, ctx } = await open(combo, `/runs/${seeded.paused}?view=overview`)
      const where = comboName(combo)
      try {
        const rl = await page.evaluate(() => {
          const items = [...document.querySelectorAll<HTMLElement>('[data-rl]')].filter(el => el.offsetParent !== null && getComputedStyle(el).display !== 'none')
          const line = items[0]?.parentElement
          const lineRight = line?.getBoundingClientRect().right ?? 0
          return {
            kpis: items.map(el => el.dataset.kpi ?? ''),
            sliced: items.filter(el => el.getBoundingClientRect().right > lineRight + 0.5 || el.scrollWidth > el.clientWidth + 1).map(el => (el.textContent ?? '').trim()),
            clippedV: items.filter(el => el.scrollHeight > el.clientHeight + 1).map(el => (el.textContent ?? '').trim()),
            text: line?.textContent ?? '',
          }
        })
        assert.ok(rl.kpis.includes('status') && rl.kpis.includes('spend'), `${where}: core slots visible (${rl.kpis.join(',')})`)
        assert.deepEqual(rl.sliced, [], `${where}: no partially visible KPI slot`)
        assert.deepEqual(rl.clippedV, [], `${where}: KPI slots fit their line box`)
        assert.match(rl.text, /\$999,999\.00/, `${where}: grouped USD`)
        assert.doesNotMatch(rl.text, NO_RAW)
        if (combo.width >= 1440) {
          assert.ok(rl.kpis.includes('phase') && rl.kpis.includes('requests'), `${where}: phase + requests slots at 1440 (${rl.kpis.join(',')})`)
          assert.match(rl.text, /999,999/)
          const phase = page.locator('[data-kpi=phase]')
          assert.equal(await phase.getAttribute('aria-label') ?? await phase.locator('[role=img]').getAttribute('aria-label'), 'Phase 3 of 5: Investigation')
        }
        for (const name of ['More actions', /^(Show|Hide) panel$/, 'More telemetry'] as const) {
          const box = await page.getByRole('button', { name }).first().boundingBox()
          assert.ok(box && box.x >= 0 && box.x + box.width <= combo.width + 0.5, `${String(name)} inside viewport at ${where}`)
        }
        await page.getByRole('button', { name: 'More telemetry' }).click()
        const tel = page.getByTestId('more-telemetry')
        await tel.waitFor()
        const tok = tel.locator('[data-num=tokens]')
        assert.equal((await tok.innerText()).trim(), '1.0B')
        assert.equal(await tok.getAttribute('title'), '999,999,999 tokens')
        assert.match(await tel.innerText(), /Passive/)
        await page.keyboard.press('Escape')
        // Overview stats use the same primitive.
        assert.match(await page.locator('main').innerText(), /1\.0B/)
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U7] traffic sparkline: live 60-min window, cap line, denied ticks, hover readout, quiet + full-run states', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of [L, XL]) {
      const { page, ctx } = await open(combo, `/runs/${seeded.budget}?view=overview`)
      try {
        const spark = page.getByTestId('traffic-sparkline')
        await spark.scrollIntoViewIfNeeded()
        assert.equal(await spark.getAttribute('data-window'), 'live')
        assert.equal(await spark.locator('svg path').count() >= 2, true)
        assert.equal(await page.getByTestId('traffic-cap-line').count(), 1, 'cap line drawn in scale')
        assert.match(await page.getByTestId('traffic-cap-label').innerText(), /^Cap 60\/min$/)
        assert.ok(await spark.locator('[data-traffic-denied]').count() >= 2, 'denied/error ticks')
        assert.equal(await page.getByTestId('traffic-quiet').count(), 0, 'recent traffic → no quiet notice')
        const readout = page.getByTestId('traffic-readout')
        const peak = Number(/^Peak\s+(\d+) req\/min/.exec(await readout.innerText())?.[1] ?? 0)
        assert.ok(peak >= 20 && peak <= 40, `burst peak shown in the idle readout (${peak})`)
        const box = await spark.locator('[role=img]').boundingBox()
        assert.ok(box)
        // Sweep the pointer across the last minutes: the burst bucket reads back with its denied ticks.
        const seen: string[] = []
        for (let i = 50; i < 60; i += 1) {
          await page.mouse.move(box.x + box.width * ((i + 0.5) / 60), box.y + box.height / 2)
          await delay(30)
          seen.push(await readout.innerText())
        }
        assert.ok(seen.every(r => /^\d{2}:\d{2}\s+·\s+[\d.]+ req\/min\s+·\s+\d+\s+req\s+·\s+\d+\s+denied$/.test(r.replace(/\n/g, ' ').replace(/\s+/g, ' '))), seen.join(' | '))
        assert.ok(seen.some(r => new RegExp(`\\b${peak} req/min`).test(r)), `hover finds the ${peak} req/min bucket: ${seen.join(' | ')}`)
        assert.ok(seen.some(r => /\b[1-9]\d*\s+denied/.test(r)), 'a hovered bucket carries denied responses')
        await page.getByRole('button', { name: 'Full run' }).click()
        assert.equal(await spark.getAttribute('data-window'), 'full')
        await page.getByRole('button', { name: 'Last 60 min' }).click()
        assert.deepEqual(await geometryOffenders(page), [], comboName(combo))
      } finally {
        await ctx.close()
      }
    }
    const quiet = await open(L, `/runs/${seeded.paused}?view=overview`)
    try {
      assert.match(await quiet.page.getByTestId('traffic-quiet').innerText(), /^No traffic in the last 10 min/)
    } finally {
      await quiet.ctx.close()
    }
    const done = await open(L, `/runs/${seeded.complete}?view=overview`)
    try {
      assert.equal(await done.page.getByTestId('traffic-sparkline').getAttribute('data-window'), 'full')
      assert.equal(await done.page.getByRole('button', { name: 'Full run' }).count(), 0, 'no window toggle once terminal')
      assert.equal(await done.page.getByTestId('traffic-quiet').count(), 0)
    } finally {
      await done.ctx.close()
    }
  })

  it('[U6] Needs attention lane above a 6-row Active now, grouped ×N signatures, rows stay 36px', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const { page, ctx } = await open(combo, `/runs/${seeded.paused}?view=workflow`)
      const where = comboName(combo)
      try {
        const list = page.getByRole('region', { name: 'Worker list' })
        await list.waitFor()
        const attention = page.getByTestId('workflow-attention-section')
        const active = page.getByTestId('workflow-active-section')
        assert.equal(await attention.getAttribute('aria-label'), 'Needs attention (8)')
        assert.equal(await active.getAttribute('aria-label'), 'Active now (9)')
        const [ab, cb] = [await attention.boundingBox(), await active.boundingBox()]
        assert.ok(ab && cb && ab.y + ab.height <= cb.y + 1, `${where}: Needs attention pinned above Active now`)
        assert.equal(await attention.locator('[data-wf-attention-breakdown]').innerText(), '7 failed · 1 awaiting approval')
        const upstream = attention.locator('[data-attention-group=failed][data-attention-count="5"]')
        assert.equal(await upstream.count(), 1, `${where}: five identical failures fold into one row`)
        assert.match(await upstream.locator('[data-attention-multiplier]').innerText(), /^×5$/)
        assert.match(await upstream.locator('[data-wf-reason]').innerText(), /^UpstreamTimeout after Ns waiting for the model endpoint$/)
        assert.equal(await attention.locator('[data-attention-group=failed][data-attention-count="2"]').count(), 1)
        assert.equal(await active.locator('[data-id]').count(), 6, `${where}: Active now capped at 6`)
        assert.equal(await page.locator('[data-id^="w-fail-"]').count(), 0, `${where}: collapsed failures are not duplicated in the phase groups`)
        const rows = await page.evaluate(() => {
          const region = document.querySelector('[role="region"][aria-label="Worker list"]')
          const rs = [...(region?.querySelectorAll<HTMLElement>('[data-id], [data-attention-row]') ?? [])].filter(r => r.getBoundingClientRect().height > 0)
          let overlap = 0
          for (const r of rs) {
            const kids = [...r.children].map(k => k.getBoundingClientRect()).filter(b => b.width > 0)
            for (let i = 0; i + 1 < kids.length; i += 1) if (kids[i]!.right > kids[i + 1]!.left + 1) overlap += 1
          }
          return { n: rs.length, tall: rs.filter(r => r.getBoundingClientRect().height > 37).map(r => r.textContent?.slice(0, 40)), overlap, grouped: (region?.textContent ?? '').includes('999,999 req') }
        })
        assert.ok(rows.n > 10)
        assert.deepEqual(rows.tall, [], `${where}: rows never wrap past 36px`)
        assert.equal(rows.overlap, 0, `${where}: no overlapping row cells`)
        assert.ok(rows.grouped, `${where}: 999,999 req stays exact and grouped`)
        assert.deepEqual(await geometryOffenders(page), [], where)
        await shot(page, 'workflow-triage', combo)
        // Expand the ×5 group: members appear once; Show all reveals the 3 folded active rows.
        await upstream.getByRole('button', { name: /Show 5 workers/ }).click()
        assert.equal(await page.locator('[data-id^="w-fail-"]').count(), 5)
        const toggle = page.getByTestId('workflow-active-toggle')
        assert.equal((await toggle.innerText()).trim(), 'Show all 9')
        await toggle.click()
        assert.equal(await active.locator('[data-id]').count(), 9)
        assert.equal((await toggle.innerText()).trim(), 'Show fewer')
        assert.deepEqual(await geometryOffenders(page), [], `${where} expanded`)
        await toggle.click()
        await upstream.getByRole('button', { name: /Hide 5 workers/ }).click()
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U6] worker inspector turn timeline rail: filters, collapsed successes, auto-expanded errors, windowed trace', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const { page, ctx } = await open(combo, `/runs/${seeded.paused}?view=workflow&sel=worker:${seeded.traceWorker}`)
      const where = comboName(combo)
      try {
        const pane = page.locator('aside[aria-label="Inspector"]')
        await pane.getByRole('tab', { name: /^Transcript/ }).click()
        const rail = pane.getByTestId('turn-timeline')
        await rail.waitFor().catch(async () => assert.fail(`${where}: no turn timeline; inspector reads: ${(await pane.innerText()).slice(0, 600)}`))
        assert.equal(await rail.locator('[data-rail-turn]').count(), 50, `${where}: one rail row per turn`)
        assert.ok(await rail.locator('[data-seg=error]').count() >= 5, 'error segments')
        assert.ok(await rail.locator('[data-seg=finding]').count() >= 2, 'finding segments')
        const widths = await rail.locator('[data-rail-bar]').evaluateAll(els => els.map(el => parseFloat((el as HTMLElement).style.width)))
        assert.equal(Math.max(...widths), 100)
        assert.ok(Math.min(...widths) < 20, 'bars are proportional to turn duration')
        const chips = await pane.locator('[data-turn-filter]').allInnerTexts()
        assert.deepEqual(chips.map(c => c.replace(/\s*\d+$/, '').trim()), ['All', 'Errors', 'Findings', 'Slow >10s'])
        const list = pane.getByTestId('turn-list')
        assert.equal(await list.getAttribute('data-windowed'), 'true', `${where}: 50 turns → windowed trace`)
        assert.ok(await list.locator('[data-turn]').count() <= 40, `${where}: DOM stays light`)
        const states = await list.locator('[data-tool-status]').evaluateAll(els => els.map(el => [el.getAttribute('data-tool-status'), el.hasAttribute('data-tool-open')]))
        assert.ok(states.some(([s]) => s === 'error'))
        for (const [status, isOpen] of states) assert.equal(isOpen, status === 'error' || status === 'finding', `${status} default open=${isOpen}`)
        assert.equal(await list.locator('[data-turn-head]').first().evaluate(el => getComputedStyle(el).position), 'sticky')
        await pane.locator('[data-turn-filter=errors]').click()
        const errTurns = await list.locator('[data-turn]').count()
        assert.ok(errTurns >= 5 && errTurns <= 6)
        assert.equal(await list.locator('[data-turn]').evaluateAll(els => els.every(el => !!el.querySelector('[data-tool-status=error]'))), true)
        await pane.locator('[data-turn-filter=all]').click()
        await rail.locator('[data-rail-turn="45"]').click()
        const turn45 = list.locator('[data-turn="45"]')
        await turn45.waitFor()
        await page.waitForFunction(() => {
          const el = document.querySelector('[data-turn="45"]')
          const pane = document.querySelector('aside[aria-label="Inspector"]')
          if (!el || !pane) return false
          const r = el.getBoundingClientRect()
          return r.top >= pane.getBoundingClientRect().top - 1 && r.top < window.innerHeight
        })
        assert.deepEqual(await geometryOffenders(page), [], where)
        await pane.locator('[data-turn-filter=all]').click()
        await rail.locator('[data-rail-turn="7"]').click()
        await list.locator('[data-turn="7"]').waitFor()
        await delay(150)
        await shot(page, 'workflow-inspector-timeline', combo)
      } finally {
        await ctx.close()
      }
    }
  })

  it('no page errors across B2 views', t => {
    if (skip) { t.skip(skip); return }
    assert.deepEqual(pageErrors, [])
  })
})
