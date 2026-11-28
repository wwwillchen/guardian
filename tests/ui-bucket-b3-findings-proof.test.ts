// Desktop Bucket B — PR B3: evidence-first Finding inspector + sticky Verify Fix footer ([U2]),
// the single triage-aware findings projection ([U3]) and structured proof viewers ([U5]).
//
// 1. Behavioral unit tests: triage buckets agree with the headline projection / `buildVerdict`,
//    `needs_review` never counts as confirmed, suppressed rows never reach an active severity
//    bucket, fix-state derivation, receipt normalization over malformed shapes, redaction helpers.
// 2. Playwright (seeded isolated server, 1280×720 + 1440×900, light + dark): verdict card, Proof
//    open by default, sticky Verify Fix above the fold, Triage popover (click + `t`), copy split
//    menu with in-button feedback + redacted clipboard, Needs review badge/banner, projection counts
//    across Findings tabs and Report, Suppressed tab, 72px severity column, Fix status grouping,
//    density toggle, ReceiptView diff + JSON tree, DAG rail collapse, Exchanges waterfall/tabs/
//    Reveal/Compare — all with zero horizontal overflow. `KOVO_UI_SHOTS_DIR=<dir>` captures PNGs.
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
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { CopyMorphIcon, FixStatePill } from '../src/components/run/glyphs.tsx'
import { buildVerdict, normalizeRunDetail } from '../src/components/run/model.ts'
import type { Detail, FindingRow } from '../src/components/run/model.ts'
import {
  diffExchanges, formatFindingMarkdown, isSensitiveHeader, middleTruncate, normalizeReceiptComparison,
  receiptCellText, receiptExchangeIds, REDACTED, redactForClipboard, redactHeaders,
} from '../src/components/run/views/proof-viewers.tsx'
import {
  ACTIVE_TRIAGE_BUCKETS, indexFindingFixStates, projectRunFindings, projectTriagedFindings, runFindingsScopeContext,
} from '../src/findings-view.ts'
import type { FindingsViewInputRow } from '../src/findings-view.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CI_MULT = process.env.CI ? 2 : 1
const HOOK_TIMEOUT_MS = 90_000 * CI_MULT
const SHOTS_DIR = process.env.KOVO_UI_SHOTS_DIR ?? ''
const A = 'https://app.b3-proof.example'
const B = 'https://api.b3-proof.example'
const FAKE_TOKEN = 'Bearer canary-token-0123456789abcdef'
/** Exchange ids are validated as UUIDs by `readExchange`. */
const EX = Array.from({ length: 6 }, (_, i) => `b3b3b3b3-0000-4000-8000-00000000000${i}`)

// ---------------------------------------------------------------------------
// 1. Unit tests
// ---------------------------------------------------------------------------

type Row = FindingsViewInputRow & { title: string; evidenceIds: string[]; findingKind: string }
let seq = 0
function row(over: Partial<Row> & Pick<Row, 'status'>): Row {
  seq += 1
  return { id: `u-${seq}`, origin: A, severity: 'medium', title: `Finding ${seq}`, evidenceIds: [], findingKind: 'baseline_check', verificationStatus: null, ...over }
}

function mixedRows(): Row[] {
  return [
    row({ status: 'confirmed', severity: 'critical' }),
    row({ status: 'confirmed', severity: 'high' }),
    row({ status: 'confirmed', severity: 'medium', operatorTriage: { status: 'open', severityOverride: 'high', notes: '' } }),
    row({ status: 'needs_review', severity: 'high' }),
    row({ status: 'needs_review', severity: 'low' }),
    row({ status: 'static_verified', severity: 'medium', verificationTier: 'static_verified' }),
    row({ status: 'pending', severity: 'low' }),
    row({ status: 'proposed', severity: 'low' }),
    row({ status: 'inconclusive', severity: 'medium' }),
    row({ status: 'dismissed', severity: 'high' }),
    row({ status: 'confirmed', severity: 'critical', operatorTriage: { status: 'false_positive', severityOverride: 'critical', notes: 'benign canary' } }),
    row({ status: 'confirmed', severity: 'high', operatorTriage: { status: 'accepted_risk', severityOverride: 'critical', notes: '' } }),
    row({ status: 'needs_review', severity: 'medium', operatorTriage: { status: 'false_positive', severityOverride: null, notes: '' } }),
    row({ status: 'confirmed', severity: 'high', origin: 'https://out-of-scope.example' }),
  ]
}

describe('[U3] single triage-aware findings projection', () => {
  it('bucket totals equal the headline projection counts and the All tab is the active sum', () => {
    const rows = mixedRows()
    const ctx = { approvedOrigins: [A, B] }
    const p = projectTriagedFindings(rows, ctx)
    const c = projectRunFindings(rows, ctx).counts
    assert.equal(p.counts.confirmed, c.confirmed)
    assert.equal(p.counts.needs_review, c.needsReview)
    assert.equal(p.counts.dismissed, c.dismissed)
    assert.equal(p.counts.suppressed, c.suppressed)
    assert.equal(p.counts.static_verified, c.advisories)
    assert.equal(p.counts.pending, c.pending)
    assert.equal(p.counts.inconclusive, c.inconclusive)
    assert.equal(p.counts.excluded, c.excluded)
    assert.equal(p.counts.all, ACTIVE_TRIAGE_BUCKETS.reduce((n, b) => n + p.counts[b], 0))
    assert.equal(p.rows.length, p.counts.all + p.counts.suppressed)
    assert.deepEqual([p.counts.confirmed, p.counts.needs_review, p.counts.dismissed, p.counts.suppressed, p.counts.excluded], [3, 2, 1, 3, 1])
  })

  it('needs_review is never confirmed: disposition unverified, counted under needsReview only', () => {
    const p = projectTriagedFindings(mixedRows())
    const review = p.rows.filter(r => r.finding.status === 'needs_review' && r.bucket !== 'suppressed')
    assert.equal(review.length, 2)
    for (const r of review) {
      assert.equal(r.bucket, 'needs_review')
      assert.equal(r.item.disposition, 'unverified')
      assert.notEqual(r.item.disposition, 'confirmed')
    }
    assert.ok(!p.view.confirmed.some(x => x.finding.status === 'needs_review'))
  })

  it('false_positive / accepted_risk with a severity override route to Suppressed, never Confirmed or Critical', () => {
    const p = projectTriagedFindings(mixedRows())
    const suppressed = p.rows.filter(r => r.item.suppressedBy)
    assert.equal(suppressed.length, 3)
    for (const r of suppressed) assert.equal(r.bucket, 'suppressed')
    const active = p.rows.filter(r => r.bucket !== 'suppressed')
    assert.ok(!active.some(r => r.item.suppressedBy), 'no suppressed row in an active bucket')
    assert.equal(p.view.counts.byConfirmedSeverity.critical, 1, 'only the untriaged critical counts as confirmed critical')
    assert.ok(!p.view.confirmed.some(x => x.suppressedBy))
  })

  it('effective severity is severityOverride ?? severity and keeps the machine severity', () => {
    const p = projectTriagedFindings(mixedRows())
    const overridden = p.rows.find(r => r.finding.operatorTriage?.status === 'open')!
    assert.equal(overridden.effectiveSeverity, 'high')
    assert.equal(overridden.machineSeverity, 'medium')
    assert.equal(overridden.severityOverridden, true)
    assert.ok(p.rows.filter(r => r !== overridden && !r.finding.operatorTriage?.severityOverride).every(r => !r.severityOverridden))
  })

  it('agrees with buildVerdict for the same run (scope context mirrors the headline)', () => {
    const findings = mixedRows() as unknown as FindingRow[]
    const d = normalizeRunDetail(fakeDetail({ findings }))
    const v = buildVerdict(d, d.findings, false)
    const p = projectTriagedFindings(d.findings, runFindingsScopeContext(d.run, d.facts))
    assert.equal(p.counts.confirmed, v.confirmed)
    assert.equal(p.counts.suppressed, v.suppressed)
    assert.equal(p.counts.dismissed, v.n.dismissed)
    assert.equal(p.counts.static_verified + p.counts.confirmed, v.reportable)
  })
})

describe('[U3] fix lifecycle derivation', () => {
  it('derives none / verifying / verified_fixed / still_reproducible from retests and retest workers', () => {
    const t = 1_700_000_000_000
    const fs = [{ id: 'a' }, { id: 'b' }, { id: 'c', replaySpecId: 'rs-c' }, { id: 'd' }, { id: 'e' }, { id: 'f-1' }]
    const m = indexFindingFixStates(fs, {
      retestRuns: [
        { findingId: 'a', verdict: 'reproduced', createdAt: t },
        { findingId: 'a', verdict: 'fixed', createdAt: t + 10 },
        { findingId: 'b', verdict: 'fixed', createdAt: t + 10 },
        { findingId: 'b', verdict: 'reproduced', createdAt: t + 20 },
        { findingId: 'd', verdict: 'inconclusive', createdAt: t },
        null,
        { findingId: 42 as unknown as string, verdict: 'fixed' },
      ],
      assignments: [
        { phase: 'retest', status: 'running', objective: 'Verify Fix for replay rs-c' },
        { phase: 'retest', status: 'complete', objective: 'e' },
        { phase: 'retest', status: 'queued', objective: 'Verify Fix for finding f-12' },
        null,
      ],
      replaySpecs: [{ id: 'rs-c', findingId: 'c' }, null],
    })
    assert.deepEqual(m.get('a'), { state: 'verified_fixed', at: t + 10 })
    assert.deepEqual(m.get('b'), { state: 'still_reproducible', at: t + 20 })
    assert.equal(m.get('c')?.state, 'verifying')
    assert.equal(m.get('d')?.state, 'none')
    assert.deepEqual(m.get('e'), { state: 'none', at: null })
    assert.equal(m.get('f-1')?.state, 'none', 'ids match as whole tokens, never as substrings (f-1 vs f-12, a vs "replay")')
    assert.doesNotThrow(() => indexFindingFixStates([{ id: 'x' }], { retestRuns: null, assignments: undefined, replaySpecs: null }))
  })

  it('fix-state pill crossfades colour/opacity (never transform) and renders no copy for none', () => {
    const none = renderToStaticMarkup(createElement(FixStatePill, { state: 'none' }))
    const fixed = renderToStaticMarkup(createElement(FixStatePill, { state: 'verified_fixed' }))
    const repro = renderToStaticMarkup(createElement(FixStatePill, { state: 'still_reproducible' }))
    assert.ok(fixed.includes('Verified fixed') && fixed.includes('text-ok'))
    assert.ok(repro.includes('Still reproducible') && repro.includes('text-danger'))
    assert.ok(!none.includes('Not retested'))
    for (const html of [none, fixed, repro]) {
      assert.ok(html.includes('transition-[color,background-color,border-color,opacity]'))
      assert.ok(html.includes('duration-150'))
      assert.ok(!html.includes('transform'))
    }
    const morph = renderToStaticMarkup(createElement(CopyMorphIcon, { copied: true }))
    assert.ok(morph.includes('transition-[opacity,scale]') && !morph.includes('transition-[opacity,transform]'))
    assert.ok(morph.includes('motion-reduce:transition-[opacity]'))
  })
})

describe('[U5] receipt normalization and redaction helpers', () => {
  it('never throws and renders placeholders on null / malformed receipt shapes', () => {
    const shapes: unknown[] = [null, undefined, 7, 'raw text', [], [null], { stepStatuses: 'nope' }, { stepStatuses: [null, 3, { role: 5 }] }, { lastVerificationDiff: { a: 1 } }]
    for (const diff of shapes) {
      for (const proofReceipt of [null, 'x', { receipt: { exchangeIds: 'x' } }, { receipt: null }]) {
        const cmp = normalizeReceiptComparison({ diff, proofReceipt })
        assert.equal(typeof cmp.paired, 'boolean')
        for (const r of cmp.rows) {
          for (const v of [r.control, r.variant]) assert.ok(!/undefined|null|\[object/.test(v), `cell copy ${v}`)
        }
        assert.ok(!/undefined|null/.test(receiptCellText(cmp.control)))
      }
    }
    const empty = normalizeReceiptComparison({})
    assert.equal(empty.paired, false)
    assert.equal(receiptCellText(empty.control), '— · — · —')
    assert.equal(empty.tree, null)
  })

  it('pairs control vs. variant from step roles and flags differing cells', () => {
    const cmp = normalizeReceiptComparison({
      diff: { stepStatuses: [{ id: 'c1', role: 'control', status: 403, bodyLen: 88 }, { id: 'p1', role: 'probe', status: 200, bodyLen: 2048, mediaType: 'application/json' }], failedStepId: null },
      control: { durationMs: 41, bodySha256: 'sha256-aaaa', respHeaders: { 'Set-Cookie': 'sid=abc', 'Content-Length': '88' } },
      variant: { durationMs: 63, bodySha256: 'sha256-bbbb', respHeaders: { 'Content-Length': '2048' } },
    })
    assert.equal(cmp.paired, true)
    const byKey = Object.fromEntries(cmp.rows.map(r => [r.key, r]))
    assert.equal(byKey.status!.control, '403')
    assert.equal(byKey.status!.variant, '200')
    assert.equal(byKey.status!.differs, true)
    assert.equal(byKey.bytes!.differs, true)
    assert.equal(byKey['h:set-cookie']!.control, REDACTED, 'sensitive receipt headers are redacted')
    assert.equal(receiptCellText(cmp.control), '403 · 88 B · 41 ms')
    const tree = cmp.tree as { lastVerificationDiff: { failedStepId: unknown } }
    assert.equal(tree.lastVerificationDiff.failedStepId, null)
  })

  it('reads receipt exchange ids defensively', () => {
    assert.deepEqual(receiptExchangeIds({ receipt: { exchangeIds: ['x-1', 2, '', 'x-2'] } }), ['x-1', 'x-2'])
    for (const v of [null, 1, 'x', { receipt: 'x' }, { receipt: { exchangeIds: null } }]) assert.deepEqual(receiptExchangeIds(v), [])
  })

  it('redacts sensitive headers by default with an explicit reveal', () => {
    const h = {
      Authorization: FAKE_TOKEN, Cookie: 'sid=1', 'Set-Cookie': 'sid=2', 'X-API-Key': 'k', 'Proxy-Authorization': 'Basic Zm9vOmJhcg==',
      'X-Auth-Token': 't', 'Content-Type': 'application/json', 'X-Trace': `see ${FAKE_TOKEN}`,
    }
    const red = redactHeaders(h)
    for (const k of ['Authorization', 'Cookie', 'Set-Cookie', 'X-API-Key', 'Proxy-Authorization', 'X-Auth-Token']) {
      assert.equal(red[k], REDACTED, k)
      assert.ok(isSensitiveHeader(k))
    }
    assert.equal(red['Content-Type'], 'application/json')
    assert.ok(!red['X-Trace']!.includes('canary-token'), 'secret-shaped values inside other headers are masked')
    assert.equal(redactHeaders(h, true).Authorization, FAKE_TOKEN)
    for (const junk of [null, undefined, 'x', 7, ['a']]) assert.deepEqual(redactHeaders(junk), {})
    assert.equal(redactHeaders({ a: null, b: { n: 1 } }).b, '{"n":1}')
  })

  it('clipboard redaction walks arbitrary shapes, survives cycles, and masks credential-shaped strings', () => {
    const cyc: Record<string, unknown> = { authorization: FAKE_TOKEN, nested: { note: `token ${FAKE_TOKEN}`, list: [FAKE_TOKEN, 1, null] } }
    cyc.self = cyc
    const out = JSON.stringify(redactForClipboard(cyc))
    assert.ok(!out.includes('canary-token'), out)
    assert.ok(out.includes(REDACTED))
    for (const v of [null, undefined, 0, true, 'plain', []]) assert.doesNotThrow(() => redactForClipboard(v))
    const md = formatFindingMarkdown({ id: 'f-1', title: null, reason: `Observed ${FAKE_TOKEN} reflected`, exchangeIds: ['x-1'] }, { status: 'Confirmed by replay', severity: 'High', fix: null })
    assert.ok(md.startsWith('# Untitled finding'))
    assert.ok(!md.includes('canary-token') && !/undefined|null/.test(md))
  })

  it('middle-truncates long values to the 64-char budget and diffs exchanges safely', () => {
    const long = 'a'.repeat(40) + 'MIDDLE' + 'z'.repeat(40)
    const t = middleTruncate(long, 64)
    assert.equal(t.length, 64)
    assert.ok(t.startsWith('aaaa') && t.endsWith('zzzz') && t.includes('…'))
    assert.equal(middleTruncate('short'), 'short')
    const d = diffExchanges(
      { method: 'GET', pathAndQuery: '/a', status: 403, durationMs: 10, respHeaders: { 'set-cookie': 's=1', vary: 'x' }, bodyPreview: 'line1\nsame' },
      { method: 'GET', pathAndQuery: '/a', status: 200, durationMs: 10, respHeaders: { vary: 'x' }, bodyPreview: 'line2\nsame' },
    )
    assert.equal(d.rows.find(r => r.key === 'status')!.differs, true)
    assert.equal(d.rows.find(r => r.key === 'timing')!.differs, false)
    assert.equal(d.rows.find(r => r.key === 'h:set-cookie')!.control, REDACTED)
    assert.deepEqual(d.body.map(l => l.same), [false, true])
    assert.doesNotThrow(() => diffExchanges(null, undefined))
  })
})

function fakeDetail(overrides: Record<string, unknown> = {}): Detail {
  const createdAt = 1_700_000_000_000
  const candidates = [{ id: 'asset-1', origin: A, source: 'seed', thirdParty: false }, { id: 'asset-2', origin: B, source: 'seed', thirdParty: false }]
  const base = {
    run: {
      id: 'run-1', projectId: 'proj-1', workspaceId: 'ws-1', tenantId: 'default', originalGoal: 'Verify auth', goal: 'Verify auth',
      goalRevision: 1, scopeRevision: 1, coordinatorId: 'coord-1', phase: 'investigation', status: 'paused', sourceMode: 'public', capabilityTier: 2,
      approvalPolicy: 'auto_review', approvedEndpointPatterns: [], approvedPersonaIds: [], roundNo: 1, budgetUsd: 25, budgetRequests: 0, spentUsd: 1,
      spentTokens: 1000, spentRequests: 10, turnsUsed: 2, maxRpsPerOrigin: 5, workerConcurrency: 6, workerMaxTurns: 150, dynamicStepBudget: null,
      multiTrialEnabled: true, phase0CompletedAt: null, reviewPlan: null, candidates, approved: ['asset-1', 'asset-2'], authOrigins: [], assetOrigins: [],
      environmentMode: 'prod_readonly', routeDenylist: [], createdAt,
    },
    project: { id: 'proj-1', workspaceId: 'ws-1', tenantId: 'default', name: 'Demo', environment: 'public', seeds: [A], defaultScope: [A], labConfig: null, sandboxWriteAllowlist: [], createdAt },
    personas: [], specs: [], threatModel: null, chainSteps: [], facts: [], graphEdges: [], digests: [], assignments: [], approvals: [], exchangesSummary: [],
    coverageEntries: [], endpoints: [], endpointParams: [], apiDependencies: [], labTelemetry: [], openProofGaps: [], sastRuns: [], surfaceProbes: [],
    patchProposals: [], replaySpecs: [], retestRuns: [], findings: [], provenanceCounts: { deterministic_floor: 0, agent_confirmed: 0, static_advisory: 0, open_proof_gap: 0 },
    messages: [], boardMembers: [], boardMessages: [], evidence: [], reports: [], cursor: 0, hasModel: true, labTarget: null, localLabEnvEnabled: false,
  }
  return { ...base, ...overrides } as unknown as Detail
}

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
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-b3-proof-'))
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
  if (!healthy) { await stop(); throw new Error(`serve.ts failed to start.\n${output}`) }
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

const LONG_REMEDIATION = Array.from({ length: 14 }, (_, i) =>
  `Step ${i + 1}: enforce the tenant ownership check in \`InvoiceExportController#show\` before serialising, scope every \`ExportJob.find\` by \`current_tenant.id\`, and re-run the differential probe (control vs. variant) to confirm the variant now returns 403.`).join(' ')

function compositeReceipt() {
  const hops = Array.from({ length: 6 }, (_, i) => ({
    hopId: `hop-${i + 1}`,
    surface: i === 2 ? 'graphql' : 'http',
    target: { origin: A, method: i % 2 ? 'POST' : 'GET', pathAndQuery: `/api/v2/tenants/acme/exports/job-${1000 + i}/artifacts?expand=line-items,adjustments&page=${i}` },
    claimedDelta: `Hop ${i + 1} hands the export capability to the next step`,
    consumedCapabilities: i ? [`cap:export-${i}`] : [],
    producedCapabilities: [`cap:export-${i + 1}`],
  }))
  const causalEdges = hops.slice(1).map((h, i) => ({ kind: 'value_binding', fromHopId: hops[i]!.hopId, toHopId: h.hopId, capabilityHandle: `cap:export-${i + 1}` }))
  return {
    compositeReceipt: {
      chainId: 'chain-b3-six-hop', terminalVulnClass: 'dual_tenant_abac', replayMode: 'fresh_clean_replay', hops, causalEdges,
      terminalImpact: { terminalHopId: 'hop-6', claimedImpact: 'Cross-tenant invoice export disclosure', oracleFamily: 'dual_tenant_abac' },
    },
    compositeVerification: {
      confirmed: true, terminalOracleFamily: 'dual_tenant_abac', reason: 'Mode-A clean replay verified every causal handoff.',
      verifiedEdges: causalEdges.map(e => ({ fromHopId: e.fromHopId, toHopId: e.toHopId, kind: e.kind, verified: true })),
    },
    hopActors: Object.fromEntries(hops.map(h => [h.hopId, 'tenant_a_member'])),
  }
}

const VERIFY_DIFF = {
  verdict: 'confirmed', controlPassed: true, failedStepId: null, retriesRemaining: 0,
  observedNote: 'Variant response carried sibling-tenant invoice line items while the control response was denied by the policy layer',
  requestHeaders: { authorization: FAKE_TOKEN },
  stepStatuses: [{ id: 'c1', role: 'control', status: 403, bodyLen: 88, mediaType: 'application/json' }, { id: 'p1', role: 'probe', status: 200, bodyLen: 2048, mediaType: 'application/json' }],
}

interface Seeded { runId: string }

function seedRun(dataDir: string, runId: string): Seeded {
  const now = Date.now()
  const started = now - 3 * 3_600_000
  const candidates = [A, B].map((origin, i) => ({ id: `cand-${i + 1}`, origin, source: 'Project seed', thirdParty: false }))
  return withDb(dataDir, db => {
    const meta = db.prepare('SELECT project_id, goal_revision FROM runs WHERE id = ?').get(runId) as { project_id: string; goal_revision: number }
    const g = meta.goal_revision
    db.prepare(`UPDATE runs SET phase = 'investigation', status = 'paused', scope_revision = 1, candidates = ?, approved = ?, created_at = ? WHERE id = ?`)
      .run(JSON.stringify(candidates), JSON.stringify(candidates.map(c => c.id)), started, runId)
    db.prepare('DELETE FROM assignments WHERE run_id = ?').run(runId)
    db.prepare(
      `INSERT INTO assignments (id, run_id, asset_id, step_id, input_assignment_id, phase, status, scope_revision, goal_revision,
         session_id, attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins, title, objective, outcome, created_at)
       VALUES ('w-1', ?, 'cand-1', NULL, NULL, 'investigation', 'complete', 1, ?, 's-1', 0, 40, 12, 30, '[]', ?, 'Differential probe worker', 'Control vs. variant comparison on the approved surface.', 'Done.', ?)`,
    ).run(runId, g, JSON.stringify([A]), started)

    const insX = db.prepare(
      `INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query,
         persona_handle, status, media_type, req_headers, resp_headers, body_preview, body_artifact_id, body_sha256, secret_matches, duration_ms, created_at)
       VALUES (?, ?, 'w-1', 1, ?, ?, '[]', ?, ?, ?, ?, 'application/json', ?, ?, ?, NULL, ?, '[]', ?, ?)`,
    )
    const durs = [41, 63, 240, 1800, 4200, 9]
    for (let i = 0; i < 6; i += 1) {
      const origin = i < 4 ? A : B
      const req = { accept: 'application/json', authorization: FAKE_TOKEN, cookie: 'sid=canary-session-cookie-value' }
      const resp: Record<string, string> = {
        'content-type': 'application/json', 'content-length': String(i === 0 ? 88 : 2048), 'set-cookie': `sid=canary-${i}; HttpOnly`,
        'strict-transport-security': 'max-age=63072000', 'x-request-correlation-identifier-for-distributed-tracing-pipeline': 'c'.repeat(90),
      }
      const body = i === 0 ? JSON.stringify({ error: 'forbidden' }, null, 2) : JSON.stringify({ items: [{ id: 100 + i, tenant: 'sibling' }], page: i }, null, 2)
      insX.run(EX[i]!, runId, origin, origin, i % 2 ? 'POST' : 'GET', `/api/v2/tenants/acme/invoices/${100000 + (i % 2)}/line-items?expand=adjustments&page=${i}`,
        i === 1 ? 'tenant-b-member' : null, i === 0 ? 403 : 200, JSON.stringify(req), JSON.stringify(resp), body, `sha256-${String(i).repeat(16)}`, durs[i]!, started + i * 60_000)
    }

    const insRs = db.prepare(
      `INSERT INTO replay_specs (id, run_id, finding_id, assignment_id, scope_revision, goal_revision, spec, spec_sha256, source_origins, last_verification_diff, proof_verdict, proof_receipt, created_at)
       VALUES (?, ?, ?, 'w-1', 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    const spec = (title: string) => JSON.stringify({
      version: 1, kind: 'http_chain', origin: A, title, category: 'broken-access-control', cwe: 'CWE-639', severity: 'high', severityRationale: 'Cross-tenant read.',
      impact: 'Tenant data read.', remediation: 'Enforce ownership.', recheckInstructions: 'Replay as tenant B.', assertionsJq: '{ controlPassed: true }', expectedImpactEvents: ['invariant_violation'],
      steps: [{ id: 'c1', role: 'control', description: 'Control', expectedStatus: 403, request: { origin: A, method: 'GET', pathAndQuery: '/api/items/1', followRedirects: false } }],
    })
    const insF = db.prepare(
      `INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, replay_spec_id, provenance, verification_class,
         source_origins, status, severity, cwe, origin, triage_status, finding)
       VALUES (?, ?, 'cand-1', ?, 'chain', ?, 'multi_step_chain', ?, 'agent_only', ?, ?, ?, ?, 'CWE-639', ?, ?, ?)`,
    )
    const defs: Array<{ id: string; title: string; status: string; severity: string; triage?: { status: string; severityOverride: string | null; notes: string }; rs?: boolean; retest?: 'fixed' | 'reproduced'; ex?: string[] }> = [
      { id: 'f-chain', title: 'Cross-tenant invoice export through a six-hop capability chain', status: 'confirmed', severity: 'critical', rs: true, ex: EX.slice(0, 5) },
      { id: 'f-fixed', title: 'Invoice PDF readable by sibling tenant', status: 'confirmed', severity: 'high', rs: true, retest: 'fixed', ex: [EX[2]!] },
      { id: 'f-repro', title: 'Line-item export ignores tenant scope', status: 'confirmed', severity: 'medium', rs: true, retest: 'reproduced', ex: [EX[3]!] },
      { id: 'f-override', title: 'Billing contact enumeration', status: 'confirmed', severity: 'medium', rs: true, triage: { status: 'open', severityOverride: 'high', notes: '' }, ex: [EX[1]!] },
      { id: 'f-review', title: 'Possible cross-tenant adjustment read held for review', status: 'needs_review', severity: 'medium', ex: [EX[4]!] },
      { id: 'f-dismissed', title: 'Stale cache header ruled out on replay', status: 'dismissed', severity: 'low' },
      { id: 'f-fp', title: 'Benign canary echo flagged as reflection', status: 'confirmed', severity: 'critical', rs: true, triage: { status: 'false_positive', severityOverride: 'low', notes: 'Benign canary verification echo' }, ex: [EX[5]!] },
    ]
    const reportFindings: unknown[] = []
    for (const [i, d] of defs.entries()) {
      const rsId = d.rs ? `rs-${d.id}` : null
      const finding = {
        id: d.id, origin: A, title: d.title, cwe: 'CWE-639', category: 'broken-access-control', severity: d.severity, status: d.status,
        reason: 'Control vs. variant differential: the control request was denied while the variant returned sibling-tenant data. A benign canary confirmed the read path.',
        impact: 'Unauthorized read of another tenant’s billing data.',
        verification: 'Automated replay', remediation: d.id === 'f-chain' ? LONG_REMEDIATION : 'Scope the lookup by the authenticated tenant.',
        recheck: 'Re-run Verify Fix and confirm the variant returns 403.',
        evidenceIds: [], exchangeIds: d.ex ?? [], scopeRevision: 1, findingKind: 'multi_step_chain', ...(rsId ? { replaySpecId: rsId } : {}),
      }
      reportFindings.push(finding)
      const stored = d.triage ? { ...finding, operatorTriage: { ...d.triage, updatedAt: now } } : finding
      if (rsId) {
        insRs.run(rsId, runId, d.id, g, spec(d.title), `sha-${i}`, JSON.stringify([A]), JSON.stringify(VERIFY_DIFF), 'confirmed',
          JSON.stringify(d.id === 'f-chain' ? compositeReceipt() : { receipt: { exchangeIds: d.ex ?? [] }, verification: { confirmed: true, reason: 'Variant differed from control.' } }), started)
      }
      insF.run(d.id, runId, g, `b3-case-${i}`, rsId, 'runtime_confirmed', JSON.stringify([A]), d.status, d.severity, A, d.triage?.status ?? 'open', JSON.stringify(stored))
      if (d.retest) {
        db.prepare(`INSERT INTO retest_runs (id, project_id, run_id, finding_id, replay_spec_id, scope_revision, verdict, summary, evidence_ids, exchange_ids, created_at)
          VALUES (?, ?, ?, ?, ?, 1, ?, ?, '[]', '[]', ?)`).run(`rt-${d.id}`, meta.project_id, runId, d.id, rsId, d.retest, d.retest === 'fixed' ? 'Variant now denied (403).' : 'Variant still returns sibling data.', now - 600_000)
      }
    }
    db.prepare('INSERT INTO reports (id, run_id, version, partial, body, created_at) VALUES (?, ?, 1, 0, ?, ?)').run(`rep-${runId.slice(0, 8)}`, runId, JSON.stringify({
      goal: 'Verify tenant isolation', capabilityTier: 2, scope: candidates, scopeRevision: 1, goalRevision: g, coverage: [], findings: reportFindings, gaps: [],
    }), now)
    return { runId }
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
const size = (c: Combo) => `${c.width}x${c.height}`

/** Horizontal overflow offenders inside the run shell and inspector (empty = clean). */
async function overflowOffenders(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = []
    const visible = (el: Element) => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 }
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth + 1) out.push(`document ${doc.scrollWidth}>${doc.clientWidth}`)
    const sel = 'main, aside[aria-label="Inspector"], aside[aria-label="Inspector"] .overflow-auto, main .overflow-auto, [data-slot="receipt-view"], [data-slot="json-tree"], [data-slot="dag-rail"], [data-slot="exchange-tabs"], [data-slot="exchange-compare"], [data-slot="verdict-card"]'
    for (const el of document.querySelectorAll(sel)) {
      if (visible(el) && el.scrollWidth > el.clientWidth + 1) out.push(`${el.tagName.toLowerCase()}[${el.getAttribute('data-slot') ?? el.className.toString().slice(0, 40)}] ${el.scrollWidth}>${el.clientWidth}`)
    }
    for (const r of document.querySelectorAll('main [data-id]')) {
      const edge = r.getBoundingClientRect().right
      for (const c of r.children) if (visible(c) && c.getBoundingClientRect().right > edge + 1) out.push(`row ${r.getAttribute('data-id')} cell spills "${(c.textContent ?? '').trim().slice(0, 24)}"`)
    }
    for (const b of document.querySelectorAll<HTMLElement>('main button, aside button')) {
      if (!visible(b) || getComputedStyle(b).overflow === 'visible') continue
      if (b.scrollHeight > b.clientHeight + 2) out.push(`button clipped "${(b.textContent ?? '').trim().slice(0, 40)}"`)
    }
    return out
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

async function shot(page: Page, name: string): Promise<void> {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  await page.screenshot({ path: join(SHOTS_DIR, `${name}.png`) })
}

describe('B3 findings proof rendered DOM + geometry (Playwright)', () => {
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
    await page.getByLabel('Project name').fill('B3 findings proof')
    await page.getByLabel('Sites').fill([A, B].join('\n'))
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

  async function open(combo: Combo, path: string, opts: { clipboard?: boolean } = {}): Promise<{ page: Page; ctx: BrowserContext }> {
    const ctx = await browser!.newContext({ viewport: { width: combo.width, height: combo.height }, colorScheme: combo.theme, storageState })
    if (opts.clipboard) await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: kovo!.origin })
    await ctx.addInitScript({ content: 'globalThis.__name = globalThis.__name || (f => f)' })
    await ctx.addInitScript((theme: string) => { try { localStorage.setItem('kovo-appearance', theme) } catch { /* noop */ } }, combo.theme)
    const page = await ctx.newPage()
    page.setDefaultTimeout(20_000 * CI_MULT)
    page.on('pageerror', err => { pageErrors.push(`${path}: ${err instanceof Error ? err.message : String(err)}`) })
    await page.goto(`${kovo!.origin}${path}`, { waitUntil: 'load' })
    await page.locator('main').first().waitFor({ state: 'attached' })
    await waitHydrated(page)
    await settle(page)
    return { page, ctx }
  }
  const findingPath = (id: string) => `/runs/${seeded!.runId}?view=findings&sel=finding:${id}`
  const inspector = (page: Page) => page.locator('aside[aria-label="Inspector"]')

  for (const combo of COMBOS) {
    it(`evidence-first inspector, needs-review and exchanges render cleanly at ${size(combo)} ${combo.theme}`, { timeout: 120_000 * CI_MULT }, async t => {
      if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
      const offenders: string[] = []
      {
        const { page, ctx } = await open(combo, findingPath('f-chain'))
        try {
          const aside = inspector(page)
          await aside.locator('[data-slot="receipt-view"]').waitFor({ state: 'visible' })
          await aside.locator('[data-slot="dag-rail"]').waitFor({ state: 'visible' })
          const card = await aside.locator('[data-slot="verdict-card"]').boundingBox()
          assert.ok(card && card.y < 140, `verdict card leads the inspector: ${JSON.stringify(card)}`)
          const verify = await aside.getByTestId('verify-fix').boundingBox()
          assert.ok(verify && verify.y >= 0 && verify.y + verify.height <= combo.height, `Verify Fix above the fold: ${JSON.stringify(verify)}`)
          assert.ok(await aside.locator('[data-slot="proof-beat"]').isVisible(), 'Proof is open by default for a confirmed finding')
          assert.equal(await aside.locator('[data-slot="fix-header-tag"]').count(), 0, 'no fix tag before any retest')
          for (const o of await overflowOffenders(page)) offenders.push(`inspector: ${o}`)
          await shot(page, `findings-inspector-${combo.theme}-${size(combo)}`)
        } finally { await ctx.close() }
      }
      {
        const { page, ctx } = await open(combo, findingPath('f-review'))
        try {
          const aside = inspector(page)
          const banner = aside.locator('[data-slot="needs-review-banner"]')
          await banner.waitFor({ state: 'visible' })
          const badge = aside.locator('[data-slot="verdict-card"]').getByText('Needs review', { exact: true }).first()
          assert.ok(await badge.isVisible(), 'amber Needs review badge in the verdict card')
          const tone = await badge.evaluate(el => (el.closest('span[class*="warn"]') ? 'warn' : el.parentElement?.className ?? ''))
          assert.equal(tone, 'warn')
          assert.ok(await page.locator('main [data-id="f-review"]').getByText('Needs review', { exact: true }).first().isVisible(), 'row keeps the Needs review badge')
          for (const o of await overflowOffenders(page)) offenders.push(`needs-review: ${o}`)
          await shot(page, `findings-needs-review-${combo.theme}-${size(combo)}`)
        } finally { await ctx.close() }
      }
      {
        const { page, ctx } = await open(combo, `/runs/${seeded.runId}?view=exchanges&sel=exchange:${EX[0]}`)
        try {
          const aside = inspector(page)
          await aside.locator('[data-slot="exchange-tabs"]').waitFor({ state: 'visible' })
          await aside.getByLabel('Compare with exchange').selectOption(EX[1]!)
          await aside.locator('[data-slot="exchange-diff"]').waitFor({ state: 'visible' })
          for (const o of await overflowOffenders(page)) offenders.push(`exchanges: ${o}`)
          await shot(page, `exchanges-inspector-${combo.theme}-${size(combo)}`)
        } finally { await ctx.close() }
      }
      assert.deepEqual(offenders, [], `${size(combo)} ${combo.theme}`)
    })
  }

  it('[U2] sticky footer survives long remediation; Triage popover toggles by click and `t`; copy menu morphs in-button and redacts', { timeout: 90_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, findingPath('f-chain'), { clipboard: true })
    try {
      const aside = inspector(page)
      await aside.locator('[data-slot="receipt-view"]').waitFor({ state: 'visible' })
      const scroller = aside.locator('.overflow-auto').first()
      const scroll = await scroller.evaluate(el => ({ sh: el.scrollHeight, ch: el.clientHeight }))
      assert.ok(scroll.sh > scroll.ch + 200, 'body is long enough to scroll')
      await scroller.evaluate(el => { el.scrollTop = el.scrollHeight })
      await settle(page)
      const verify = await aside.getByTestId('verify-fix').boundingBox()
      assert.ok(verify && verify.y >= 0 && verify.y + verify.height <= 720, `Verify Fix stays pinned after scrolling: ${JSON.stringify(verify)}`)
      assert.ok(await aside.getByTestId('verify-fix').evaluate(el => el.className.includes('bg-accent')), 'Verify Fix is the filled primary action')

      const popover = aside.locator('[data-slot="triage-popover"]')
      assert.equal(await popover.count(), 0, 'triage form is not in the body flow')
      await aside.getByTestId('triage-toggle').click()
      await popover.waitFor({ state: 'visible' })
      const pop = await popover.boundingBox()
      assert.ok(pop && pop.x >= 1280 - 404 && pop.x + pop.width <= 1280, `popover stays inside the pane: ${JSON.stringify(pop)}`)
      await page.keyboard.press('Escape')
      await popover.waitFor({ state: 'detached' })
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
      await page.keyboard.press('t')
      await popover.waitFor({ state: 'visible' })
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur())
      await page.keyboard.press('t')
      await popover.waitFor({ state: 'detached' })
      assert.equal(await aside.locator('[data-slot="triage-dot"]').count(), 0, 'no dot when triage is unset')

      await aside.getByTestId('copy-menu').click()
      await aside.getByRole('menuitem', { name: 'Copy finding link' }).click()
      await aside.locator('[data-testid="copy-primary"] [data-slot="copy-morph"][data-copied]').waitFor({ state: 'attached' })
      assert.match(await aside.getByTestId('copy-primary').innerText(), /Copied/)
      assert.ok((await page.evaluate(() => navigator.clipboard.readText())).includes('sel=finding:f-chain'))
      assert.equal(await page.getByTestId('toast-region').filter({ hasText: /Copied/ }).count(), 0, 'no global copy toast')

      await aside.getByTestId('copy-menu').click()
      await aside.getByRole('menuitem', { name: 'Copy receipt JSON (redacted)' }).click()
      await page.waitForFunction(async () => (await navigator.clipboard.readText()).includes('compositeReceipt'))
      const receiptJson = await page.evaluate(() => navigator.clipboard.readText())
      assert.ok(!receiptJson.includes('canary-token'), 'receipt JSON clipboard export is redacted')
      assert.ok(receiptJson.includes('[redacted]'))

      await aside.getByTestId('copy-primary').click()
      await page.waitForFunction(async () => (await navigator.clipboard.readText()).startsWith('curl'))
      const curl = await page.evaluate(() => navigator.clipboard.readText())
      assert.ok(!curl.includes('canary-token') && !curl.includes('canary-session-cookie-value'), 'cURL clipboard export is redacted')
    } finally { await ctx.close() }
  })

  it('[U3] tab totals match the Report; Suppressed tab holds the false positive; 72px severity column, Fix status grouping and density', { timeout: 90_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[2]!, `/runs/${seeded.runId}?view=findings`)
    try {
      // Tab counts by label, whether a tab is inline or folded into the toolbar's "More · n" menu.
      const tabCounts = async (): Promise<Record<string, number>> => {
        const out: Record<string, number> = {}
        const read = async (sel: string) => {
          for (const txt of await page.locator(sel).allInnerTexts()) {
            const m = /^(.*?)\s*([\d,]+)$/.exec(txt.replace(/\s+/g, ' ').trim())
            if (m) out[m[1]!] = Number(m[2]!.replace(/,/g, ''))
          }
        }
        await read('main [role="tablist"] [role="tab"]')
        const more = page.locator('main [role="tablist"] button', { hasText: /^More · / })
        if (await more.count()) {
          await more.click()
          await read('main [role="tablist"] [role="menu"] button')
          await page.keyboard.press('Escape')
        }
        return out
      }
      const tc = await tabCounts()
      const counts = { confirmed: tc.Confirmed ?? -1, needs_review: tc['Needs review'] ?? -1, dismissed: tc.Dismissed ?? -1 }
      assert.deepEqual(counts, { confirmed: 4, needs_review: 1, dismissed: 1 })
      assert.equal(await page.locator('main [data-id="f-fp"]').count(), 0, 'suppressed row is not in All')
      const critical = page.locator('main [data-group="critical"]')
      assert.equal(await critical.locator('[data-slot="group-count"]').innerText(), '1', 'Critical group holds only the untriaged critical')

      // Rows clip their own paint (content-visibility), so check every cell stays inside its row.
      const spill = await page.locator('main [data-id]').evaluateAll(rows => rows.flatMap(r => {
        const edge = r.getBoundingClientRect().right
        return [...r.children].filter(c => c.getBoundingClientRect().width > 0 && c.getBoundingClientRect().right > edge + 1).map(c => `${r.getAttribute('data-id')}: ${(c.textContent ?? '').slice(0, 24)}`)
      }))
      assert.deepEqual(spill, [], 'no row cell spills past its row edge')
      const widths = async () => page.locator('main [data-slot="sev-cell"]').evaluateAll(els => [...new Set(els.map(e => Math.round(e.getBoundingClientRect().width)))])
      assert.deepEqual(await widths(), [72], 'severity column is 72px in severity grouping')
      const overrideTitle = await page.locator('main [data-id="f-override"]').getAttribute('title')
      assert.ok(overrideTitle?.includes('machine severity Medium'), `override tooltip: ${overrideTitle}`)
      assert.equal(await page.locator('main [data-id="f-repro"] [data-fix-state="still_reproducible"]').innerText(), 'Still reproducible')
      assert.equal(await page.locator('main [data-id="f-fixed"] [data-fix-state="verified_fixed"]').innerText(), 'Verified fixed')

      const display = page.getByTitle('Display options (⇧G cycles grouping)')
      await display.click()
      await page.getByRole('radio', { name: 'Fix status' }).click()
      const heads = await page.locator('main [data-group]').evaluateAll(els => els.map(e => e.getAttribute('data-group')))
      assert.deepEqual(heads, ['still_reproducible', 'verified_fixed', 'none'])
      assert.deepEqual(await widths(), [72], 'severity column persists in Fix status grouping')
      await page.getByRole('radio', { name: 'Category' }).click()
      assert.deepEqual(await widths(), [72], 'severity column persists in Category grouping')
      await page.getByRole('radio', { name: 'Compact' }).click()
      const rowH = async () => page.locator('main [data-id]').evaluateAll(els => [...new Set(els.map(e => Math.round(e.getBoundingClientRect().height)))])
      assert.deepEqual(await rowH(), [30], 'compact rows are 30px')
      await page.getByRole('radio', { name: 'Comfortable' }).click()
      assert.deepEqual(await rowH(), [36], 'comfortable rows are 36px')
      await page.getByRole('radio', { name: 'Severity' }).first().click()
      await page.keyboard.press('Escape')

      await page.locator('[data-slot="low-priority-fold"]').click()
      await page.locator('[role="menuitem"][data-tab="suppressed"]').click()
      await page.locator('main [data-id="f-fp"]').waitFor({ state: 'visible' })
      const suppressedCount = (await tabCounts()).Suppressed ?? -1
      assert.equal(suppressedCount, 1)
      assert.deepEqual(await page.locator('main [data-group]').evaluateAll(els => els.map(e => e.getAttribute('data-group'))), ['false_positive'], 'suppressed rows group by reason, never severity')
      assert.equal(await page.locator('main [data-id="f-fp"]').getAttribute('data-bucket'), 'suppressed')
      for (const o of await overflowOffenders(page)) assert.fail(`findings list overflow: ${o}`)

      await page.goto(`${kovo!.origin}/runs/${seeded.runId}?view=report`, { waitUntil: 'load' })
      await page.locator('[data-slot="report-triage-counts"]').waitFor({ state: 'visible' })
      const reportCount = async (k: string) => Number(await page.locator(`[data-slot="report-triage-counts"] [data-count="${k}"]`).innerText())
      assert.deepEqual(
        { confirmed: await reportCount('confirmed'), needs_review: await reportCount('needs_review'), dismissed: await reportCount('dismissed'), suppressed: await reportCount('suppressed') },
        { ...counts, suppressed: suppressedCount },
        'Report and Findings tabs read the same projection',
      )
    } finally { await ctx.close() }
  })

  it('[U5] ReceiptView diff + JSON tree; six-hop DAG rail collapses behind "Show 2 more hops"', { timeout: 90_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, findingPath('f-chain'))
    try {
      const aside = inspector(page)
      const receipt = aside.locator('[data-slot="receipt-view"]')
      await receipt.waitFor({ state: 'visible' })
      const differs = await receipt.locator('[data-slot="receipt-table"] [data-differs]').evaluateAll(els => els.map(e => ({ cls: e.className, text: (e.textContent ?? '').slice(0, 30) })))
      assert.ok(differs.length >= 2, 'status and bytes differ between control and variant')
      assert.ok(differs.every(d => d.cls.includes('bg-warn-soft')), 'differing rows are tinted bg-warn-soft')
      assert.match(await aside.locator('[data-slot="control-variant"] [data-cell="control"]').innerText(), /^403 · 88 B · /)

      await receipt.locator('[data-slot="json-tree"] > button').click()
      const nulls = receipt.locator('[data-slot="json-null"]')
      await nulls.first().waitFor({ state: 'visible' })
      assert.equal(await nulls.first().innerText(), '—')
      const trunc = receipt.locator('[data-slot="json-truncated"]').first()
      const before = await trunc.innerText()
      assert.ok(before.includes('…') && before.length <= 66, `middle-truncated: ${before}`)
      await trunc.click()
      assert.ok((await trunc.innerText()).length > 66, 'click expands the full value')
      assert.ok(!(await receipt.innerText()).includes('canary-token'), 'JSON tree redacts credential values')
      const leafCopies = await receipt.locator('[data-slot="json-leaf-copy"]').count()
      assert.ok(leafCopies > 3, 'every leaf has a copy button')
      const geo = await receipt.evaluate(el => ({ sw: el.scrollWidth, cw: el.clientWidth }))
      assert.ok(geo.sw <= geo.cw + 1, `receipt view has no horizontal overflow: ${JSON.stringify(geo)}`)

      const rail = aside.locator('[data-slot="dag-rail"]')
      assert.equal(await rail.locator('[data-slot="dag-hop"]').count(), 4)
      const more = rail.locator('[data-slot="dag-more"]')
      assert.equal(await more.innerText(), 'Show 2 more hops')
      assert.ok((await rail.locator('[data-slot="dag-edge"]').first().innerText()).includes('value binding ✓'))
      await more.click()
      assert.equal(await rail.locator('[data-slot="dag-hop"]').count(), 6)
      assert.equal(await more.innerText(), 'Show fewer hops')
      const node = await rail.locator('[data-slot="dag-hop"] > span.rounded-full').first().boundingBox()
      assert.ok(node && Math.round(node.width) === 18 && Math.round(node.height) === 18, `18px step nodes: ${JSON.stringify(node)}`)
      const railGeo = await rail.evaluate(el => ({ sw: el.scrollWidth, cw: el.clientWidth }))
      assert.ok(railGeo.sw <= railGeo.cw + 1, `rail has no horizontal overflow: ${JSON.stringify(railGeo)}`)
      assert.deepEqual(await overflowOffenders(page), [])
    } finally { await ctx.close() }
  })

  it('[U5] Exchanges: log-scale waterfall, Request/Response/Timing/Raw tabs, redacted headers with Reveal, Compare with… diff', { timeout: 90_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[2]!, `/runs/${seeded.runId}?view=exchanges&sel=exchange:${EX[0]}`)
    try {
      const bars = await page.locator('main [data-slot="waterfall"]').evaluateAll(els => els.map(e => {
        const i = e.querySelector('i')
        return { track: Math.round(e.getBoundingClientRect().width), fill: i ? i.getBoundingClientRect().width : 0, row: e.closest('[data-id]')?.getAttribute('data-id') }
      }))
      assert.equal(bars.length, 6)
      assert.deepEqual([...new Set(bars.map(b => b.track))], [56], 'bounded waterfall width')
      const fill = Object.fromEntries(bars.map(b => [b.row, b.fill]))
      assert.ok(fill[EX[4]!]! > fill[EX[3]!]! && fill[EX[3]!]! > fill[EX[0]!]! && fill[EX[0]!]! > fill[EX[5]!]!, `durations order the bars: ${JSON.stringify(fill)}`)
      assert.ok(fill[EX[0]!]! > 56 * 0.3, 'log scale keeps a 41 ms exchange legible next to 4.2 s')

      const aside = inspector(page)
      const tabs = aside.locator('[data-slot="exchange-tabs"]')
      await tabs.waitFor({ state: 'visible' })
      assert.deepEqual(await tabs.getByRole('tab').allInnerTexts(), ['Request', 'Response', 'Timing', 'Raw'])
      const setCookie = tabs.locator('[data-slot="header-table"] tr', { hasText: 'set-cookie' }).locator('td').nth(1)
      assert.equal(await setCookie.innerText(), '[redacted]')
      await tabs.locator('[data-slot="reveal-toggle"]').first().click()
      assert.match(await setCookie.innerText(), /^sid=canary-0/)
      await tabs.locator('[data-slot="reveal-toggle"]').first().click()
      await tabs.getByRole('tab', { name: 'Request' }).click()
      const auth = tabs.locator('[data-slot="header-table"] tr', { hasText: 'authorization' }).locator('td').nth(1)
      assert.equal(await auth.innerText(), '[redacted]')
      await tabs.getByRole('tab', { name: 'Timing' }).click()
      assert.match(await tabs.locator('[data-slot="timing-panel"]').innerText(), /41\s*ms total/)
      await tabs.getByRole('tab', { name: 'Raw' }).click()
      const raw = await tabs.locator('[data-slot="exchange-raw"]').innerText()
      assert.ok(raw.startsWith('GET /api/v2') && !raw.includes('canary-token'), 'raw view is redacted by default')

      await aside.getByLabel('Compare with exchange').selectOption(EX[1]!)
      const diff = aside.locator('[data-slot="exchange-diff"]')
      await diff.waitFor({ state: 'visible' })
      const status = diff.locator('[role="row"]', { hasText: 'Status' })
      assert.equal(await status.getAttribute('data-differs'), 'true')
      assert.ok((await status.getAttribute('class'))?.includes('bg-warn-soft'))
      assert.ok(await aside.locator('[data-slot="exchange-body-diff"] .bg-warn-soft').count() > 0, 'body preview diff marks differing lines')
      for (const slot of ['exchange-tabs', 'exchange-compare']) {
        const g = await aside.locator(`[data-slot="${slot}"]`).evaluate(el => ({ sw: el.scrollWidth, cw: el.clientWidth }))
        assert.ok(g.sw <= g.cw + 1, `${slot} has no horizontal overflow: ${JSON.stringify(g)}`)
      }
      assert.deepEqual(await overflowOffenders(page), [])
      assert.match(await aside.innerText(), /Cited by/)
    } finally { await ctx.close() }
  })

  it('no page errors across B3 views', t => {
    if (skip) { t.skip(skip); return }
    assert.deepEqual(pageErrors, [])
  })
})
