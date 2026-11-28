// Desktop Bucket B — Wave 2C: overlay inspector pane with an accessible, snapping resizer ([U9]) and
// the workflow graph's follow-live camera, collapsed completed phases and semantic zoom ([U10]).
//
// 1. Pure behavior: pane width clamps / snap points / magnetic snapping / keyboard steps / overlay vs.
//    docked mode; phase completion, default collapse, layout projection, zoom tiers, minimap gating and
//    the follow-live target.
// 2. Playwright (seeded run: completed discovery + threat model, live investigation with a finding) at
//    1280×720 and 1440×900 in light + dark (+ reduced motion): overlay/docked inspector, pin + widen,
//    separator keyboard + pointer snapping + persistence, focus return, collapsed phase lanes, follow-live
//    engagement, semantic zoom tiers and top-bar geometry. Set `KOVO_W2C_SHOTS_DIR=<dir>` for screenshots.
//
// No production source is read as text: everything is asserted through exported behavior or the DOM.
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
import type { Browser, BrowserContext, Page } from '@playwright/test'
import {
  computeSnappedPaneWidth,
  maxPaneWidth,
  PANE_DEFAULT,
  PANE_KEY,
  PANE_MAX_CEILING,
  PANE_MIN,
  PANE_OVERLAY_MAX_VP,
  PANE_OVERLAY_MIN_VP,
  PANE_PIN_KEY,
  PANE_SNAP_THRESHOLD,
  paneSnapPoints,
  resolvePaneMode,
  stepPaneWidth,
} from '../src/components/run/shell.tsx'
import {
  COLLAPSED_PHASE_GAP,
  COLLAPSED_PHASE_W,
  defaultCollapsedPhases,
  isCompletedPhaseHead,
  LEGIBILITY_FLOOR_K,
  MINIMAP_OVERFLOW_RATIO,
  projectWorkflowLayout,
  selectFollowLiveTarget,
  SEMANTIC_LOD_K,
  semanticZoomTier,
  shouldShowMinimap,
} from '../src/components/run/views/workflow-graph.tsx'
import { WF } from '../src/components/run/views/workflow-layout.ts'
import type { WfEdge, WfHead, WfLayout, WfNode } from '../src/components/run/views/workflow-layout.ts'
import type { Assignment } from '../src/components/run/model.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CI_MULT = process.env.CI ? 2 : 1
const HOOK_TIMEOUT_MS = 120_000 * CI_MULT
const SHOTS_DIR = process.env.KOVO_W2C_SHOTS_DIR ?? ''

// ---------------------------------------------------------------------------
// 1. Pure behavior
// ---------------------------------------------------------------------------

describe('[U9] inspector pane geometry helpers', () => {
  it('exposes the pane contract constants', () => {
    assert.equal(PANE_KEY, 'kovo-rw-pane')
    assert.equal(PANE_PIN_KEY, 'kovo-rw-pane-pinned')
    assert.deepEqual([PANE_MIN, PANE_DEFAULT, PANE_MAX_CEILING, PANE_SNAP_THRESHOLD], [320, 404, 760, 4])
    assert.deepEqual([PANE_OVERLAY_MIN_VP, PANE_OVERLAY_MAX_VP], [900, 1439])
  })

  it('maxPaneWidth: 58% of the viewport, floored, within [320, 760]; 640 without a viewport', () => {
    assert.equal(maxPaneWidth(1280), 742)
    assert.equal(maxPaneWidth(1440), 760)
    assert.equal(maxPaneWidth(1000), 580)
    assert.equal(maxPaneWidth(400), 320)
    assert.equal(maxPaneWidth(0), 640)
    assert.equal(maxPaneWidth(-5), 640)
    assert.equal(maxPaneWidth(Number.NaN), 640)
  })

  it('paneSnapPoints: 360 / 480 / half the viewport, clamped, sorted and unique', () => {
    assert.deepEqual(paneSnapPoints(1280), [360, 480, 640])
    assert.deepEqual(paneSnapPoints(1440), [360, 480, 720])
    assert.deepEqual(paneSnapPoints(960), [360, 480], 'half of 960 coincides with 480')
    assert.deepEqual(paneSnapPoints(600), [320, 348], '360 and 480 clamp to the 348px max; half clamps to the 320 floor')
  })

  it('computeSnappedPaneWidth: magnetic 4px snap, unsnapped outside it, clamped to min / max', () => {
    for (const p of [360, 480, 640]) {
      for (const d of [-4, -2, 0, 3, 4]) assert.deepEqual(computeSnappedPaneWidth(p + d, 1280), { width: p, snappedTo: p }, `${p}${d >= 0 ? '+' : ''}${d}`)
      assert.deepEqual(computeSnappedPaneWidth(p + 5, 1280), { width: p + 5, snappedTo: null })
      assert.deepEqual(computeSnappedPaneWidth(p - 5, 1280), { width: p - 5, snappedTo: null })
    }
    assert.deepEqual(computeSnappedPaneWidth(722, 1440), { width: 720, snappedTo: 720 })
    assert.deepEqual(computeSnappedPaneWidth(100, 1280), { width: 320, snappedTo: null })
    assert.deepEqual(computeSnappedPaneWidth(5000, 1280), { width: 742, snappedTo: null })
    assert.deepEqual(computeSnappedPaneWidth(5000, 1440), { width: 760, snappedTo: null })
  })

  it('stepPaneWidth: ←/→ ±24, ⇧ ±96, Home / End / Enter, other keys ignored', () => {
    assert.deepEqual(stepPaneWidth(404, 'ArrowLeft', false, 1280), { width: 428 })
    assert.deepEqual(stepPaneWidth(404, 'ArrowLeft', true, 1280), { width: 500 })
    assert.deepEqual(stepPaneWidth(404, 'ArrowRight', false, 1280), { width: 380 })
    assert.deepEqual(stepPaneWidth(404, 'ArrowRight', true, 1280), { width: 320 }, 'clamped to the minimum')
    assert.deepEqual(stepPaneWidth(730, 'ArrowLeft', false, 1280), { width: 742 }, 'clamped to the maximum')
    assert.deepEqual(stepPaneWidth(500, 'Home', false, 1280), { width: 320 })
    assert.deepEqual(stepPaneWidth(500, 'End', false, 1280), { width: 742 })
    assert.deepEqual(stepPaneWidth(500, 'End', false, 1440), { width: 760 })
    assert.deepEqual(stepPaneWidth(600, 'Enter', false, 1280), { width: 404, reset: true })
    for (const k of ['[', ']', 'G', '/', 'ArrowUp', 'a', ' ']) assert.equal(stepPaneWidth(404, k, k === 'G', 1280), null, k)
  })

  it('resolvePaneMode: overlay at 900–1439px, docked elsewhere, an explicit pin / float wins', () => {
    assert.equal(resolvePaneMode(1280, null), 'overlay')
    assert.equal(resolvePaneMode(900, null), 'overlay')
    assert.equal(resolvePaneMode(1439, null), 'overlay')
    assert.equal(resolvePaneMode(1440, null), 'docked')
    assert.equal(resolvePaneMode(1920, null), 'docked')
    assert.equal(resolvePaneMode(899, null), 'docked')
    assert.equal(resolvePaneMode(1280, true), 'docked')
    assert.equal(resolvePaneMode(1440, false), 'overlay')
    assert.equal(resolvePaneMode(1920, false), 'overlay')
  })
})

const head = (phase: string, x: number, w: number, n: number, done: number, live = false, earlier = 0): WfHead => ({ phase, x, w, n, done, live, earlier, expanded: [] })
const worker = (id: string, phase: string, x: number, y: number, status: string, createdAt: number): WfNode => ({
  id, kind: 'worker', phase, pi: 0, row: 0, x, y, createdAt,
  a: { id, phase, status, createdAt, title: id } as unknown as Assignment,
})
function layoutOf(heads: WfHead[], nodes: WfNode[], links: [string, string][], report: WfNode | null = null): WfLayout {
  const byId = new Map(nodes.map(n => [n.id, n]))
  if (report) byId.set(report.id, report)
  const edges: WfEdge[] = links.map(([from, to]) => ({ key: from + '>' + to, from, to, kind: 'handoff', n: 1 }))
  const inc = new Map<string, string[]>(), out = new Map<string, string[]>()
  for (const e of edges) { inc.set(e.to, [...(inc.get(e.to) ?? []), e.from]); out.set(e.from, [...(out.get(e.from) ?? []), e.to]) }
  const W = Math.max(...heads.map(h => h.x + h.w))
  const H = Math.max(WF.HH + WF.NH, ...nodes.map(n => n.y + WF.NH))
  return { nodes, byId, edges, inc, out, heads, W, H, report, history: new Map(), stacks: { of: new Map(), groups: new Map() } }
}

/** discovery (3/3) · threat model (4/4) · investigation (live, 2 of 4) · verification (empty). */
function runningLayout(): WfLayout {
  return layoutOf(
    [head('discovery', 0, 264, 3, 3), head('threat_model', 356, 264, 4, 4), head('investigation', 712, 548, 4, 2, true), head('verification', 1352, 264, 0, 0)],
    [
      worker('d1', 'discovery', 0, 58, 'complete', 1), worker('t1', 'threat_model', 356, 58, 'complete', 2),
      worker('i1', 'investigation', 712, 58, 'complete', 3), worker('i2', 'investigation', 996, 160, 'running', 4),
      worker('i3', 'investigation', 996, 262, 'running', 6), worker('i4', 'investigation', 712, 364, 'paused', 9),
    ],
    [['d1', 't1'], ['t1', 'i1'], ['i1', 'i2'], ['i1', 'i3']],
  )
}

describe('[U10] workflow graph helpers', () => {
  it('exposes the semantic-zoom / legibility / lane / minimap constants', () => {
    assert.deepEqual([SEMANTIC_LOD_K, LEGIBILITY_FLOOR_K, COLLAPSED_PHASE_W, COLLAPSED_PHASE_GAP, MINIMAP_OVERFLOW_RATIO], [0.8, 0.85, 196, 48, 2])
  })

  it('isCompletedPhaseHead: finished, not live, not the current phase, not the report, has workers', () => {
    assert.equal(isCompletedPhaseHead(head('discovery', 0, 264, 3, 3), 'investigation'), true)
    assert.equal(isCompletedPhaseHead(head('discovery', 0, 264, 3, 3), 'discovery'), false, 'current phase stays open')
    assert.equal(isCompletedPhaseHead(head('discovery', 0, 264, 3, 3, true), 'investigation'), false, 'live phase')
    assert.equal(isCompletedPhaseHead(head('discovery', 0, 264, 3, 2), 'investigation'), false, 'unfinished / failed workers')
    assert.equal(isCompletedPhaseHead(head('verification', 0, 264, 0, 0), 'investigation'), false, 'no workers')
    assert.equal(isCompletedPhaseHead(head('report', 0, 264, 1, 1), 'complete'), false, 'report')
  })

  it('defaultCollapsedPhases: a running run folds every finished phase', () => {
    assert.deepEqual([...defaultCollapsedPhases(runningLayout().heads, 'investigation')].sort(), ['discovery', 'threat_model'])
  })

  it('defaultCollapsedPhases: a finished run keeps its final worker phase open', () => {
    const heads = [head('discovery', 0, 264, 3, 3), head('threat_model', 356, 264, 4, 4), head('investigation', 712, 264, 5, 5), head('verification', 1068, 264, 2, 2), head('report', 1424, 264, 1, 1)]
    assert.deepEqual([...defaultCollapsedPhases(heads, 'complete')].sort(), ['discovery', 'investigation', 'threat_model'])
    assert.deepEqual([...defaultCollapsedPhases(heads.slice(0, 1), 'complete')], [], 'a single finished phase stays open')
    const withFailure = [head('discovery', 0, 264, 3, 3), head('threat_model', 356, 264, 4, 3)]
    assert.deepEqual([...defaultCollapsedPhases(withFailure, 'complete')], ['discovery'], 'a phase with a failed worker is still active work')
  })

  it('projectWorkflowLayout: folds phases to lanes, compacts x, hides their nodes and edges', () => {
    const L = runningLayout()
    const snapshot = JSON.stringify([L.heads, L.nodes.map(n => [n.id, n.x])])
    const { layout: P, collapsedHeads } = projectWorkflowLayout(L, new Set(['discovery', 'threat_model']))
    assert.deepEqual(P.heads.map(h => [h.phase, h.x, h.w]), [
      ['discovery', 0, COLLAPSED_PHASE_W],
      ['threat_model', COLLAPSED_PHASE_W + COLLAPSED_PHASE_GAP, COLLAPSED_PHASE_W],
      ['investigation', 2 * (COLLAPSED_PHASE_W + COLLAPSED_PHASE_GAP), 548],
      ['verification', 2 * (COLLAPSED_PHASE_W + COLLAPSED_PHASE_GAP) + 548 + WF.PG, 264],
    ])
    assert.deepEqual(collapsedHeads.map(c => [c.head.phase, c.x, c.w, c.workerCount]), [['discovery', 0, 196, 3], ['threat_model', 244, 196, 4]])
    assert.deepEqual(P.nodes.map(n => [n.id, n.x, n.y]), [['i1', 488, 58], ['i2', 772, 160], ['i3', 772, 262], ['i4', 488, 364]])
    assert.deepEqual([...P.byId.keys()].sort(), ['i1', 'i2', 'i3', 'i4'])
    assert.deepEqual(P.edges.map(e => e.key), ['i1>i2', 'i1>i3'], 'edges into / out of folded phases are hidden')
    assert.deepEqual(P.inc.get('i1') ?? [], [])
    assert.equal(P.W, 488 + 548 + WF.PG + 264)
    assert.equal(P.H, 364 + WF.NH)
    assert.equal(JSON.stringify([L.heads, L.nodes.map(n => [n.id, n.x])]), snapshot, 'the input layout is not mutated')
  })

  it('projectWorkflowLayout: folding one middle phase shifts only later columns; an empty set is the identity', () => {
    const L = runningLayout()
    const { layout: P } = projectWorkflowLayout(L, new Set(['threat_model']))
    assert.deepEqual(P.heads.map(h => [h.phase, h.x]), [['discovery', 0], ['threat_model', 356], ['investigation', 600], ['verification', 600 + 548 + WF.PG]])
    assert.equal(P.byId.get('d1')?.x, 0)
    assert.equal(P.byId.get('i1')?.x, 600)
    assert.equal(P.byId.has('t1'), false)
    assert.deepEqual(P.edges.map(e => e.key), ['i1>i2', 'i1>i3'])
    const open = projectWorkflowLayout(L, new Set())
    assert.equal(open.layout, L)
    assert.deepEqual(open.collapsedHeads, [])
    assert.deepEqual(open.layout.edges.map(e => e.key), ['d1>t1', 't1>i1', 'i1>i2', 'i1>i3'], 'expanding restores every edge')
  })

  it('projectWorkflowLayout: lifts visible cards when the rows above them belonged to folded phases', () => {
    const L = layoutOf(
      [head('threat_model', 0, 264, 4, 4), head('investigation', 356, 264, 2, 1, true)],
      [worker('t1', 'threat_model', 0, 58, 'complete', 1), worker('t4', 'threat_model', 0, 364, 'complete', 2), worker('i1', 'investigation', 356, 364, 'complete', 3), worker('i2', 'investigation', 356, 466, 'running', 4)],
      [['t4', 'i1'], ['i1', 'i2']],
    )
    const { layout: P } = projectWorkflowLayout(L, new Set(['threat_model']))
    assert.deepEqual(P.nodes.map(n => [n.id, n.x, n.y]), [['i1', 244, WF.HH], ['i2', 244, WF.HH + 102]], 'the top visible row starts under the phase headers')
    assert.equal(P.H, WF.HH + 102 + WF.NH)
    assert.deepEqual(projectWorkflowLayout(L, new Set()).layout.nodes.map(n => n.y), [58, 364, 364, 466], 'unfolded rows are untouched')
  })

  it('semanticZoomTier: compact below 80%, full from 80%', () => {
    assert.equal(semanticZoomTier(0.79), 'compact')
    assert.equal(semanticZoomTier(0.5), 'compact')
    assert.equal(semanticZoomTier(0.8), 'full')
    assert.equal(semanticZoomTier(1.2), 'full')
  })

  it('shouldShowMinimap: only when the scaled graph exceeds twice the viewport', () => {
    assert.equal(shouldShowMinimap(1400, 500, 1000, 600, 1), false)
    assert.equal(shouldShowMinimap(2001, 500, 1000, 600, 1), true)
    assert.equal(shouldShowMinimap(1000, 1300, 1000, 600, 1), true)
    assert.equal(shouldShowMinimap(4000, 500, 1000, 600, 0.5), false, 'scaled content is what counts')
    assert.equal(shouldShowMinimap(9000, 9000, 0, 600, 1), false, 'no viewport yet')
  })

  it('selectFollowLiveTarget: newest running worker, else newest paused, else the live phase', () => {
    const L = runningLayout()
    const t = selectFollowLiveTarget(L)
    assert.equal(t.node?.id, 'i3', 'running beats a newer paused worker; the newest running wins')
    assert.equal(t.head?.phase, 'investigation')
    const pausedOnly = layoutOf(L.heads, L.nodes.map(n => n.a!.status === 'running' ? worker(n.id, n.phase, n.x, n.y, 'complete', n.createdAt) : n), [])
    assert.equal(selectFollowLiveTarget(pausedOnly).node?.id, 'i4')
    const idle = layoutOf(L.heads, L.nodes.map(n => worker(n.id, n.phase, n.x, n.y, 'complete', n.createdAt)), [])
    assert.deepEqual(selectFollowLiveTarget(idle), { node: null, head: L.heads[2] }, 'falls back to the live phase head')
    const done = layoutOf(L.heads.map(h => ({ ...h, live: false })), idle.nodes, [])
    assert.deepEqual(selectFollowLiveTarget(done), { node: null, head: null })
  })
})

// ---------------------------------------------------------------------------
// 2. Playwright: rendered behavior, geometry and screenshots
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
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-w2c-'))
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

const ORIGINS = ['https://app.acme-cloud.example', 'https://api.acme-cloud.example']
const MIN = 60_000
const uid = (n: number) => `2c2c2c2c-0000-4000-8000-${String(n).padStart(12, '0')}`
const W = {
  disc: [uid(1), uid(2), uid(3)],
  tm: [uid(11), uid(12), uid(13), uid(14)],
  invDone: [uid(21), uid(22)],
  invLive: [uid(23), uid(24)],
}
const FINDING_ID = 'f-w2c-tenant-read'

interface Seeded { project: string; run: string }

/**
 * A paused run (the server loop never executes a cloned row) whose investigation phase still has two
 * running workers, two completed ones and a finding; discovery and threat model are fully complete.
 */
function seedRun(dataDir: string, baseRunId: string): Seeded {
  const now = Date.now()
  const runId = `${baseRunId.slice(0, 24)}a2c100000000`
  const candidates = ORIGINS.map((origin, i) => ({ id: `cand-${i + 1}`, origin, source: 'Project seed', thirdParty: false }))
  return withDb(dataDir, db => {
    const meta = db.prepare('SELECT project_id, goal_revision FROM runs WHERE id = ?').get(baseRunId) as { project_id: string; goal_revision: number }
    cloneRun(db, baseRunId, runId, {
      status: 'paused', phase: 'investigation', capability_tier: 2, approval_policy: 'auto_review', scope_revision: 1,
      candidates: JSON.stringify(candidates), approved: JSON.stringify(candidates.map(c => c.id)), spent_requests: 420, budget_requests: 5000,
      spent_usd: 1.4, budget_usd: 25, created_at: now - 3 * 60 * MIN, goal: 'Verify tenant isolation on the billing API with control vs. variant differential probes',
    })
    const insW = db.prepare(
      `INSERT INTO assignments (id, run_id, asset_id, step_id, input_assignment_id, phase, status, scope_revision, goal_revision,
         session_id, attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins, title, objective, outcome, created_at)
       VALUES (?, ?, 'cand-1', NULL, ?, ?, ?, 1, ?, ?, 0, 60, ?, ?, '[]', ?, ?, ?, ?, ?)`,
    )
    let t = now - 170 * MIN
    const w = (id: string, phase: string, status: string, input: string | null, title: string) => {
      t += 4 * MIN
      insW.run(id, runId, input, phase, status, meta.goal_revision, `s-${id}`, status === 'running' ? 7 : 18, status === 'running' ? 12 : 40,
        JSON.stringify([ORIGINS[1]]), title, 'Control vs. variant comparison on the approved surface.', status === 'complete' ? 'No issue found.' : null, t)
    }
    w(W.disc[0]!, 'discovery', 'complete', null, 'Map the approved billing hosts')
    w(W.disc[1]!, 'discovery', 'complete', null, 'Enumerate API routes · api.acme-cloud.example')
    w(W.disc[2]!, 'discovery', 'complete', null, 'Fingerprint the auth surface')
    W.tm.forEach((id, i) => w(id, 'threat_model', 'complete', W.disc[i % 3]!, ['Rank tenant-isolation surfaces', 'Model invoice export flows', 'Model role boundaries', 'Rank session handling risks'][i]!))
    w(W.invDone[0]!, 'investigation', 'complete', W.tm[0]!, 'Invoice listing differential probe')
    w(W.invDone[1]!, 'investigation', 'complete', W.tm[1]!, 'Export job ownership check')
    w(W.invLive[0]!, 'investigation', 'running', W.invDone[0]!, 'Line-item read as sibling tenant')
    w(W.invLive[1]!, 'investigation', 'running', W.invDone[1]!, 'Adjustment export replay as member')

    const insX = db.prepare(
      `INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query,
         persona_handle, status, media_type, req_headers, resp_headers, body_preview, body_artifact_id, body_sha256, secret_matches, duration_ms, created_at)
       VALUES (?, ?, ?, 1, ?, ?, '[]', 'GET', ?, NULL, ?, 'application/json', '{}', '{}', '{"ok":true}', NULL, ?, '[]', 120, ?)`,
    )
    const ex = [0, 1, 2].map(i => `x-w2c-${i}`)
    ex.forEach((id, i) => insX.run(id, runId, W.invDone[0]!, ORIGINS[1], ORIGINS[1], `/api/v2/invoices/${1000 + i}/line-items`, i ? 200 : 403, `sha256-w2c-${i}`, now - 60 * MIN + i * MIN))
    const finding = {
      id: FINDING_ID, origin: ORIGINS[1], title: 'Invoice line items readable by a sibling tenant', cwe: 'CWE-639', category: 'broken-access-control',
      severity: 'high', status: 'pending', reason: 'Control vs. variant differential: the control was denied while the variant returned sibling-tenant line items.',
      verification: 'Automated replay', remediation: 'Scope the line-item lookup by the authenticated tenant.', evidenceIds: [], exchangeIds: ex, scopeRevision: 1,
    }
    db.prepare(
      `INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, provenance, verification_class,
         source_origins, status, severity, cwe, origin, triage_status, finding)
       VALUES (?, ?, 'cand-1', ?, 'chain', 'w2c-case-1', 'multi_step_chain', 'agent_only', 'runtime_confirmed', ?, 'pending', 'high', 'CWE-639', ?, 'open', ?)`,
    ).run(FINDING_ID, runId, meta.goal_revision, JSON.stringify([ORIGINS[1]]), ORIGINS[1], JSON.stringify(finding))
    return { project: meta.project_id, run: runId }
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
const comboName = (c: Combo) => `${c.width}x${c.height}-${c.theme}`

interface Box { x: number; y: number; width: number; height: number }
const overlaps = (a: Box, b: Box) => a.x < b.x + b.width - 0.5 && b.x < a.x + a.width - 0.5 && a.y < b.y + b.height - 0.5 && b.y < a.y + a.height - 0.5

/** Geometry offenders: horizontal overflow, clipped buttons (empty list = clean). */
async function geometryOffenders(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = []
    const visible = (el: Element) => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 }
    const label = (el: Element) => el.tagName.toLowerCase() + (el.getAttribute('aria-label') ? `[${el.getAttribute('aria-label')}]` : '') + (el.getAttribute('data-testid') ? `#${el.getAttribute('data-testid')}` : '')
    const doc = document.documentElement
    if (doc.scrollWidth > window.innerWidth) out.push(`document ${doc.scrollWidth}>${window.innerWidth}`)
    for (const el of document.querySelectorAll('main, aside[aria-label="Inspector"], aside[aria-label="Inspector"] .overflow-auto, main .overflow-auto, [role="navigation"][aria-label="Phases"]')) {
      if (!visible(el)) continue
      if (el.scrollWidth > el.clientWidth + 1) out.push(`${label(el)} scrollWidth ${el.scrollWidth}>${el.clientWidth}`)
    }
    for (const b of document.querySelectorAll<HTMLElement>('main button, aside button')) {
      if (!visible(b) || b.closest('[inert]') || getComputedStyle(b).overflow === 'visible') continue
      if (b.scrollHeight > b.clientHeight + 2) out.push(`clipped vertically "${(b.textContent ?? '').trim().slice(0, 40)}" ${b.scrollHeight}>${b.clientHeight}`)
    }
    return out
  })
}

async function settle(page: Page, ms = 350): Promise<void> {
  await page.evaluate(async () => {
    try { await document.fonts?.ready } catch { /* offline */ }
    await new Promise<void>(r => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  })
  await delay(ms)
}

async function waitHydrated(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    if (document.readyState !== 'complete') return false
    const el = document.querySelector('main button, nav button')
    return !!el && Object.keys(el).some(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'))
  }, undefined, { timeout: 20_000 * CI_MULT })
}

async function shot(page: Page, name: string): Promise<void> {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  // Let entrances / FLIPs finish (infinite live-dot pings excluded) so captures are settled.
  await page.waitForFunction(() => document.getAnimations().every(a => a.effect?.getTiming().iterations === Infinity || a.playState !== 'running'), undefined, { timeout: 5_000 }).catch(() => undefined)
  await delay(120)
  await page.screenshot({ path: join(SHOTS_DIR, `${name}.png`) })
}

const aside = (page: Page) => page.locator('aside[aria-label="Inspector"]')
const attr = async (page: Page, sel: string, name: string) => page.locator(sel).first().getAttribute(name)

describe('Wave 2C rendered behavior and geometry (Playwright)', () => {
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
    await page.getByLabel('Project name').fill('Wave 2C inspector + graph')
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
    seeded = seedRun(kovo.dataDir, runId)
    storageState = await ctx.storageState()
    await ctx.close()
  }, { timeout: HOOK_TIMEOUT_MS })

  after(async () => {
    await browser?.close().catch(() => undefined)
    await kovo?.stop().catch(() => undefined)
  })

  async function open(combo: Combo, path: string, opts: { reducedMotion?: boolean; init?: Record<string, string> } = {}): Promise<{ page: Page; ctx: BrowserContext }> {
    const ctx = await browser!.newContext({
      viewport: { width: combo.width, height: combo.height }, colorScheme: combo.theme, storageState,
      reducedMotion: opts.reducedMotion ? 'reduce' : 'no-preference',
    })
    await ctx.addInitScript({ content: 'globalThis.__name = globalThis.__name || (f => f)' })
    await ctx.addInitScript((a: { theme: string; init: Record<string, string> }) => {
      try {
        if (sessionStorage.getItem('w2c-init')) return
        sessionStorage.setItem('w2c-init', '1')
        localStorage.setItem('kovo-appearance', a.theme)
        for (const [k, v] of Object.entries(a.init)) localStorage.setItem(k, v)
      } catch { /* noop */ }
    }, { theme: combo.theme, init: opts.init ?? {} })
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

  const findingPath = () => `/runs/${seeded!.run}?view=findings&sel=finding:${FINDING_ID}`
  const graphPath = () => `/runs/${seeded!.run}?view=workflow&mode=graph`
  const L = COMBOS[0]!

  async function paneHeaderOffenders(page: Page): Promise<string[]> {
    return page.evaluate(() => {
      const pane = document.querySelector('aside[aria-label="Inspector"]')!
      const header = pane.querySelector('#paneInner .h-11') as HTMLElement | null
      if (!header) return ['no pane header']
      const out: string[] = []
      const pr = pane.getBoundingClientRect()
      const kids = [...header.children].filter(el => el.getBoundingClientRect().width > 0) as HTMLElement[]
      const boxes = kids.map(el => el.getBoundingClientRect())
      for (let i = 0; i < boxes.length; i++) {
        const a = boxes[i]!
        if (a.right > pr.right + 0.5 || a.left < pr.left - 0.5) out.push(`header child ${i} outside the pane`)
        if (kids[i]!.tagName === 'BUTTON' && (a.width < 27 || a.height < 27)) out.push(`button ${kids[i]!.getAttribute('aria-label')} squeezed ${a.width}x${a.height}`)
        for (let j = i + 1; j < boxes.length; j++) {
          const b = boxes[j]!
          if (a.left < b.right - 0.5 && b.left < a.right - 0.5) out.push(`header children ${i} and ${j} overlap`)
        }
      }
      if (header.scrollWidth > header.clientWidth + 1) out.push(`header overflows ${header.scrollWidth}>${header.clientWidth}`)
      return out
    })
  }

  it('[U9] overlay inspector at 1280, docked at 1440, pin + widen toggles, clean geometry in light and dark', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const where = comboName(combo)
      const { page, ctx } = await open(combo, findingPath())
      try {
        const pane = aside(page)
        await pane.getByRole('button', { name: 'Close' }).first().waitFor()
        const overlay = combo.width < 1440
        assert.equal(await pane.getAttribute('data-pane-mode'), overlay ? 'overlay' : 'docked', where)
        assert.equal(await pane.getAttribute('data-pane-open'), '', `${where}: pane open with the finding selected`)
        assert.equal(await pane.getAttribute('data-pane-width'), '404', where)
        assert.equal(Math.round((await pane.boundingBox())!.width), 404, where)
        assert.equal(await page.getByTestId('pane-overlay-edge-indicator').count(), overlay ? 1 : 0, `${where}: edge indicator only on the floating sheet`)
        if (overlay) {
          const ind = (await page.getByTestId('pane-overlay-edge-indicator').boundingBox())!
          const pb = (await pane.boundingBox())!
          assert.ok(Math.abs(ind.x - pb.x) < 1 && Math.round(ind.width) === 2 && ind.height > pb.height - 2, `${where}: 2px accent bar along the sheet's left edge`)
          // The sheet floats over the view: main keeps its full width (no grid reflow).
          assert.equal(Math.round((await page.locator('main').boundingBox())!.width), combo.width - 232, `${where}: main is not narrowed by the overlay`)
          assert.ok(pb.y <= 0.5 && Math.round(pb.height) === combo.height, `${where}: right-anchored full-height sheet`)
        } else {
          assert.equal(Math.round((await page.locator('main').boundingBox())!.width), combo.width - 232 - 404, `${where}: docked column`)
        }
        assert.deepEqual(await geometryOffenders(page), [], where)
        assert.deepEqual(await paneHeaderOffenders(page), [], where)
        await shot(page, `u9-inspector-${comboName(combo)}`)

        // Pin to dock ↔ float overlay.
        const dock = page.getByTestId('pane-dock-toggle')
        assert.equal(await dock.getAttribute('aria-pressed'), String(!overlay))
        await dock.click()
        await page.waitForFunction((m: string) => document.querySelector('aside[aria-label="Inspector"]')?.getAttribute('data-pane-mode') === m, overlay ? 'docked' : 'overlay')
        assert.equal(await dock.getAttribute('aria-pressed'), String(overlay))
        assert.equal(await page.evaluate(() => localStorage.getItem('kovo-rw-pane-pinned')), overlay ? '1' : '0')
        assert.deepEqual(await geometryOffenders(page), [], `${where} after pin toggle`)
        await dock.click()
        await page.waitForFunction((m: string) => document.querySelector('aside[aria-label="Inspector"]')?.getAttribute('data-pane-mode') === m, overlay ? 'overlay' : 'docked')

        // Widen for evidence, then restore.
        const widen = page.getByTestId('pane-widen-toggle')
        assert.equal(await widen.getAttribute('aria-pressed'), 'false')
        assert.equal(await widen.getAttribute('title'), 'Widen for evidence')
        await widen.click()
        const wide = String(Math.min(maxPaneWidth(combo.width), Math.max(560, Math.round(combo.width * 0.5))))
        await page.waitForFunction((w: string) => document.querySelector('aside[aria-label="Inspector"]')?.getAttribute('data-pane-width') === w, wide)
        assert.equal(await widen.getAttribute('aria-pressed'), 'true')
        assert.equal(await widen.getAttribute('title'), 'Restore inspector width')
        await settle(page, 120)
        assert.deepEqual(await geometryOffenders(page), [], `${where} widened`)
        await widen.click()
        await page.waitForFunction(() => document.querySelector('aside[aria-label="Inspector"]')?.getAttribute('data-pane-width') === '404')
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U9] separator: keyboard steps, magnetic pointer snap at 480, persistence, double-click reset, 320px header', { timeout: 90_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(L, findingPath())
    try {
      const sep = page.getByTestId('pane-resizer')
      await sep.waitFor()
      assert.equal(await sep.getAttribute('role'), 'separator')
      assert.equal(await sep.getAttribute('aria-orientation'), 'vertical')
      assert.equal(await sep.getAttribute('aria-valuemin'), '320')
      assert.equal(await sep.getAttribute('aria-valuemax'), '742')
      assert.equal(await sep.getAttribute('aria-valuenow'), '404')
      assert.equal(await sep.getAttribute('aria-valuetext'), '404 pixels')
      await sep.focus()
      assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('data-testid')), 'pane-resizer', 'focusable')
      const now = async () => Number(await sep.getAttribute('aria-valuenow'))
      const view = await page.evaluate(() => new URL(location.href).searchParams.get('view'))
      await page.keyboard.press('ArrowLeft')
      assert.equal(await now(), 428)
      await page.keyboard.press('Shift+ArrowLeft')
      assert.equal(await now(), 524)
      await page.keyboard.press('ArrowRight')
      assert.equal(await now(), 500)
      assert.equal(await page.evaluate(() => new URL(location.href).searchParams.get('view')), view, 'arrows never reach the global keyboard model')
      assert.equal(await attr(page, 'aside[aria-label="Inspector"]', 'data-pane-width'), '500')
      assert.equal(await page.evaluate(() => localStorage.getItem('kovo-rw-pane')), '500')
      await page.keyboard.press('Home')
      assert.equal(await now(), 320)
      assert.deepEqual(await paneHeaderOffenders(page), [], 'pane header at 320px')
      assert.deepEqual(await geometryOffenders(page), [], 'geometry at 320px')
      await page.keyboard.press('End')
      assert.equal(await now(), 742)
      await page.keyboard.press('Enter')
      assert.equal(await now(), 404)
      assert.equal(await page.evaluate(() => localStorage.getItem('kovo-rw-pane')), null, 'Enter resets to the default')

      // Pointer drag ending 2px past the 480 snap point lands exactly on it.
      const box = (await sep.boundingBox())!
      const x0 = box.x + box.width / 2, y0 = box.y + 200
      await page.mouse.move(x0, y0)
      await page.mouse.down()
      await page.mouse.move(x0 - 40, y0, { steps: 4 })
      await page.mouse.move(x0 - 78, y0, { steps: 4 })
      assert.equal(await sep.getAttribute('data-snapped'), '480')
      assert.equal(await now(), 480)
      assert.match(await page.getByTestId('pane-width-pill').innerText(), /^480px$/)
      await shot(page, 'u9-resizer-snapped-1280x720-light')
      await page.mouse.up()
      assert.equal(await page.getByTestId('pane-width-pill').count(), 0, 'the width pill only shows while dragging')
      assert.equal(await page.evaluate(() => localStorage.getItem('kovo-rw-pane')), '480')
      // Outside the 4px window the drag stays unsnapped.
      const b2 = (await sep.boundingBox())!
      await page.mouse.move(b2.x + b2.width / 2, y0)
      await page.mouse.down()
      await page.mouse.move(b2.x + b2.width / 2 - 30, y0, { steps: 4 })
      assert.equal(await now(), 510)
      assert.equal(await sep.getAttribute('data-snapped'), null)
      await page.mouse.move(b2.x + b2.width / 2, y0, { steps: 4 })
      await page.mouse.up()
      assert.equal(await now(), 480)

      await page.reload({ waitUntil: 'load' })
      await waitHydrated(page)
      await sep.waitFor()
      assert.equal(await now(), 480, 'width persists across reload')
      assert.equal(await attr(page, 'aside[aria-label="Inspector"]', 'data-pane-width'), '480')
      await sep.dblclick()
      assert.equal(await now(), 404)
      assert.equal(await page.evaluate(() => localStorage.getItem('kovo-rw-pane')), null, 'double-click clears the saved width')
    } finally {
      await ctx.close()
    }
  })

  it('[U9] closing the overlay returns focus; reduced motion fades without sliding', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const reduced of [false, true]) {
      const { page, ctx } = await open(L, findingPath(), { reducedMotion: reduced })
      try {
        const pane = aside(page)
        const close = pane.getByRole('button', { name: 'Close', exact: true })
        await close.waitFor()
        const transition = await pane.evaluate(el => getComputedStyle(el).transitionProperty)
        if (reduced) assert.ok(/\bopacity\b/.test(transition) && !/translate|transform/.test(transition), `reduced motion: fade only, no slide (${transition})`)
        else assert.match(transition, /translate/, 'the sheet slides on the compositor')
        // Focus something in the run line, then move into the sheet and close it from the keyboard.
        const outside = page.locator('main > header button:visible').first()
        await outside.focus()
        const outsideLabel = await outside.evaluate(el => el.getAttribute('aria-label') ?? el.textContent)
        assert.equal(await outside.evaluate(el => el === document.activeElement), true, 'run-line button takes focus')
        await close.focus()
        await page.keyboard.press('Enter')
        await page.waitForFunction(() => !document.querySelector('aside[aria-label="Inspector"]')?.hasAttribute('data-pane-open'))
        assert.equal(await pane.getAttribute('aria-hidden'), 'true')
        assert.equal(await pane.evaluate(el => el.hasAttribute('inert')), true)
        assert.equal(await page.evaluate(() => { const a = document.activeElement; return a ? a.getAttribute('aria-label') ?? a.textContent : null }), outsideLabel, 'focus returns to where it came from')
        await settle(page, 400)
        const tr = await pane.evaluate(el => getComputedStyle(el).translate)
        if (reduced) assert.ok(tr === 'none' || /^0px( 0px)?$/.test(tr), `no horizontal slide under reduced motion (${tr})`)
        else assert.notEqual(tr, 'none', 'collapsed sheet sits off-canvas')
        assert.equal(await pane.evaluate(el => getComputedStyle(el).opacity), '0')
        assert.deepEqual(await geometryOffenders(page), [], 'collapsed overlay leaves no overflow')
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U9] board-first Overview keeps the board docked at 1280; elsewhere an idle overlay opens the board on ]', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    {
      const { page, ctx } = await open(L, `/runs/${seeded.run}?view=overview`)
      try {
        const pane = aside(page)
        await page.getByTestId('board-pane').waitFor()
        assert.equal(await pane.getAttribute('data-pane-mode'), 'docked', 'the board is a companion column on the Overview')
        assert.equal(Math.round((await page.locator('main').boundingBox())!.width), 1280 - 232 - 404)
        assert.deepEqual(await geometryOffenders(page), [])
      } finally {
        await ctx.close()
      }
    }
    const { page, ctx } = await open(L, `/runs/${seeded.run}?view=findings`)
    try {
      const pane = aside(page)
      assert.equal(await pane.getAttribute('data-pane-mode'), 'overlay')
      assert.equal(await pane.getAttribute('data-pane-open'), null, 'nothing to inspect → the sheet stays out of the way')
      assert.equal(Math.round((await page.locator('main').boundingBox())!.width), 1280 - 232, 'the view keeps its full width')
      await page.keyboard.press(']')
      await page.waitForFunction(() => document.querySelector('aside[aria-label="Inspector"]')?.hasAttribute('data-pane-open'))
      await page.getByTestId('board-pane').waitFor()
      assert.equal(await page.getByTestId('pane-overlay-edge-indicator').count(), 0, 'no selected row → no edge indicator')
      await page.keyboard.press(']')
      await page.waitForFunction(() => !document.querySelector('aside[aria-label="Inspector"]')?.hasAttribute('data-pane-open'))
      await page.keyboard.press(']')
      await page.waitForFunction(() => document.querySelector('aside[aria-label="Inspector"]')?.hasAttribute('data-pane-open'))
    } finally {
      await ctx.close()
    }
  })

  async function graphReady(page: Page): Promise<void> {
    await page.locator('[data-wf-kind="worker"]').first().waitFor()
    await page.waitForFunction(() => !!document.querySelector('[data-zoom-tier]'))
  }
  const zoomOf = (page: Page) => page.evaluate(() => Number(getComputedStyle(document.querySelector('[aria-label^="Workflow graph"]')!).getPropertyValue('--k')))

  it('[U10] collapsed completed phases, live phase framed legibly, follow-live, clean top bar in light and dark', { timeout: 150_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS) {
      const where = comboName(combo)
      const { page, ctx } = await open(combo, graphPath())
      try {
        await graphReady(page)
        const lanes = await page.locator('[data-wf-collapsed-phase]').evaluateAll(els => els.map(el => el.getAttribute('data-wf-collapsed-phase')))
        assert.deepEqual(lanes, ['discovery', 'threat_model'], `${where}: finished phases fold into summary lanes`)
        for (const id of [...W.disc, ...W.tm]) assert.equal(await page.locator(`[data-n="${id}"]`).count(), 0, `${where}: folded phase nodes are hidden`)
        assert.equal(await page.locator('[data-wf-collapsed-phase="threat_model"] [data-wf-phase-toggle]').innerText().then(s => /Threat model · 4/.test(s)), true)
        // The live investigation phase is open and on screen at a legible zoom.
        const vp = (await page.locator('[aria-label^="Workflow graph"]').boundingBox())!
        assert.ok(await zoomOf(page) >= LEGIBILITY_FLOOR_K, `${where}: zoom ${await zoomOf(page)}`)
        const live = (await page.locator(`[data-n="${W.invLive[1]}"]`).boundingBox())!
        assert.ok(live.x >= vp.x && live.x + live.width <= vp.x + vp.width && live.y >= vp.y && live.y + live.height <= vp.y + vp.height, `${where}: newest live worker in view`)
        assert.equal(await page.getByTestId('wf-minimap').count(), 0, `${where}: small graph → no minimap`)

        // Top bar: phase breadcrumb + follow-live pill never overlap and stay inside the canvas.
        const nav = page.locator('[role="navigation"][aria-label="Phases"]')
        const follow = page.getByTestId('wf-follow-live')
        const nb = (await nav.boundingBox())!, fb = (await follow.boundingBox())!
        assert.equal(overlaps(nb, fb), false, `${where}: phase nav and follow-live overlap`)
        assert.ok(fb.x + fb.width <= vp.x + vp.width + 0.5 && nb.x >= vp.x, `${where}: top bar inside the canvas`)
        assert.equal(await nav.evaluate(el => el.scrollWidth <= el.clientWidth), true, `${where}: phase nav fits`)
        assert.equal(await follow.getAttribute('aria-pressed'), 'true', `${where}: follows live work by default`)
        assert.match(await follow.innerText(), /Following live/)
        assert.deepEqual(await geometryOffenders(page), [], where)
        await shot(page, `u10-workflow-graph-${comboName(combo)}`)

        // Manual pan disengages; clicking re-engages and re-frames the live worker.
        const sx = vp.x + vp.width * 0.5, sy = vp.y + vp.height - 60
        await page.mouse.move(sx, sy)
        await page.mouse.down()
        await page.mouse.move(sx + 60, sy - 10, { steps: 5 })
        await page.mouse.move(sx + 160, sy - 20, { steps: 5 })
        await page.mouse.up()
        assert.equal(await follow.getAttribute('aria-pressed'), 'false', `${where}: pan disengages follow-live`)
        assert.match(await follow.innerText(), /^Follow live$/)
        await follow.click()
        assert.equal(await follow.getAttribute('aria-pressed'), 'true')
        await settle(page, 400)
        const again = (await page.locator(`[data-n="${W.invLive[1]}"]`).boundingBox())!
        assert.ok(again.x >= vp.x && again.x + again.width <= vp.x + vp.width, `${where}: re-engaging frames the live worker again`)
        assert.ok(await zoomOf(page) >= LEGIBILITY_FLOOR_K)

        // Fit frames the whole graph (and disengages follow-live), so every lane is on screen.
        await page.getByRole('button', { name: 'Fit graph', exact: true }).click()
        assert.equal(await follow.getAttribute('aria-pressed'), 'false', `${where}: Fit disengages follow-live`)
        await settle(page, 450)
        // Expand a folded phase from its lane, then fold it back from the column header.
        await page.locator('[data-wf-collapsed-phase="threat_model"] [data-wf-phase-toggle="threat_model"]').click()
        const collapseBtn = page.locator('[data-wf-phase-toggle="threat_model"][aria-expanded="true"]')
        await collapseBtn.waitFor()
        assert.equal(await page.locator('[data-wf-collapsed-phase="threat_model"]').count(), 0)
        for (const id of W.tm) await page.locator(`[data-n="${id}"]`).waitFor()
        assert.match(await collapseBtn.innerText(), /Collapse/)
        await collapseBtn.click()
        await page.locator('[data-wf-collapsed-phase="threat_model"]').waitFor()
        assert.equal(await page.locator(`[data-n="${W.tm[0]}"]`).count(), 0)

        // The phase breadcrumb jumps into a folded phase by expanding it.
        await page.locator('[data-wf-phase-nav="discovery"]').click()
        await page.locator(`[data-n="${W.disc[0]}"]`).waitFor()
        assert.equal(await page.locator('[data-wf-collapsed-phase="discovery"]').count(), 0)
        assert.equal(await follow.getAttribute('aria-pressed'), 'false', 'phase nav disengages follow-live')
        await settle(page, 400)
        const d0 = (await page.locator(`[data-n="${W.disc[0]}"]`).boundingBox())!
        assert.ok(d0.x >= vp.x - 1 && d0.x < vp.x + vp.width, `${where}: camera lands on the expanded phase`)
        assert.deepEqual(await geometryOffenders(page), [], `${where} after expanding`)
      } finally {
        await ctx.close()
      }
    }
  })

  it('[U10] semantic zoom: compact cards below 80%, full cards from 80%; ⇧1 fits', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open({ ...L, theme: 'dark' }, graphPath())
    try {
      await graphReady(page)
      const root = page.locator('[data-zoom-tier]')
      assert.equal(await root.getAttribute('data-zoom-tier'), 'full')
      assert.equal(await root.getAttribute('data-lod'), null)
      const title = page.locator(`[data-n="${W.invLive[0]}"] .line-clamp-2`)
      assert.equal(await title.evaluate(el => getComputedStyle(el).fontSize), '12.5px')
      await page.getByRole('button', { name: 'Zoom out', exact: true }).click()
      await page.getByRole('button', { name: 'Zoom out', exact: true }).click()
      await page.waitForFunction(() => document.querySelector('[data-zoom-tier]')?.getAttribute('data-zoom-tier') === 'compact')
      await settle(page, 300)
      assert.ok(await zoomOf(page) < SEMANTIC_LOD_K)
      assert.equal(await root.getAttribute('data-lod'), '')
      assert.equal(await page.getByTestId('wf-follow-live').getAttribute('aria-pressed'), 'true', 'button zoom keeps following')
      assert.equal(await title.evaluate(el => getComputedStyle(el).fontSize), '18px', 'compact titles stay legible on screen')
      const compact = await page.locator('[data-wf-kind="worker"]').evaluateAll(cards => cards.map(card => {
        const kids = [...card.children].filter(c => { const r = c.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(c).position !== 'absolute' })
        const boxes = kids.map(k => k.getBoundingClientRect())
        let overlap = false
        for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
          const a = boxes[i]!, b = boxes[j]!
          if (a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5) overlap = true
        }
        const cr = card.getBoundingClientRect()
        const inside = boxes.every(b => b.left >= cr.left - 0.5 && b.right <= cr.right + 0.5 && b.top >= cr.top - 0.5 && b.bottom <= cr.bottom + 0.5)
        return { n: kids.length, overlap, inside }
      }))
      assert.ok(compact.length >= 4)
      for (const c of compact) {
        assert.equal(c.n, 2, 'compact card = status glyph + title')
        assert.equal(c.overlap, false, 'glyph and title do not overlap')
        assert.equal(c.inside, true, 'compact content stays inside the card')
      }
      assert.deepEqual(await geometryOffenders(page), [], 'compact tier geometry')
      await shot(page, 'u10-workflow-graph-lod-1280x720-dark')

      await page.getByRole('button', { name: 'Zoom in', exact: true }).click()
      await page.getByRole('button', { name: 'Zoom in', exact: true }).click()
      await page.waitForFunction(() => document.querySelector('[data-zoom-tier]')?.getAttribute('data-zoom-tier') === 'full')
      assert.equal(await root.getAttribute('data-lod'), null)
      assert.equal(await title.evaluate(el => getComputedStyle(el).fontSize), '12.5px')

      // Fit (⇧1) disengages follow-live.
      assert.equal(await page.getByTestId('wf-follow-live').getAttribute('aria-pressed'), 'true')
      await page.locator('[aria-label^="Workflow graph"]').focus()
      await page.keyboard.press('Shift+Digit1')
      await page.waitForFunction(() => document.querySelector('[data-testid="wf-follow-live"]')?.getAttribute('aria-pressed') === 'false')
      assert.match(await page.getByRole('button', { name: 'Fit graph', exact: true }).getAttribute('title') ?? '', /0 \/ ⇧1/)
    } finally {
      await ctx.close()
    }
  })

  it('[U10] selecting a worker in the graph opens the overlay; the top bar stays clear of the sheet', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(L, `${graphPath()}&sel=worker:${W.invLive[0]}`)
    try {
      await graphReady(page)
      const pane = aside(page)
      await page.waitForFunction(() => document.querySelector('aside[aria-label="Inspector"]')?.hasAttribute('data-pane-open'))
      assert.equal(await pane.getAttribute('data-pane-mode'), 'overlay')
      await settle(page, 400)
      const pb = (await pane.boundingBox())!
      const fb = (await page.getByTestId('wf-follow-live').boundingBox())!
      const nb = (await page.locator('[role="navigation"][aria-label="Phases"]').boundingBox())!
      assert.ok(fb.x + fb.width <= pb.x + 0.5, 'follow-live pill sits left of the floating sheet')
      assert.equal(overlaps(nb, fb), false)
      assert.equal(await page.getByTestId('wf-follow-live').getAttribute('aria-pressed'), 'false', 'arriving with a selection does not yank the camera')
      assert.deepEqual(await geometryOffenders(page), [])
    } finally {
      await ctx.close()
    }
  })

  it('no page errors across Wave 2C views', t => {
    if (skip) { t.skip(skip); return }
    assert.deepEqual(pageErrors, [])
  })
})
