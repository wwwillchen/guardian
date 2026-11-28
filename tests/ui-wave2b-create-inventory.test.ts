/**
 * Desktop Bucket B Wave 2B: [U12] guided create flows + [U15] dense inventory
 * table and Repo Discovery sheet.
 *
 * 1. Fast behavioural tests over the pure helpers the components render from
 *    (origin chip tokenizer, persona stepper gating, account combobox, inventory
 *    grouping/selection, project-draft persistence).
 * 2. Live Playwright journeys against the built bundle served by a hermetic
 *    `scripts/serve.ts` (temp KOVO_DATA_DIR seeded through the real Store API).
 *    GitHub discovery is served by an in-process `fetch` mock installed when this
 *    file is preloaded into the server (`KOVO_UI_W2B_GITHUB_MOCK=1`): 4 app
 *    installations × 9 repos = 36 repos across 4 orgs. No network, no secrets.
 *
 * Set `KOVO_UI_SHOTS_DIR=<dir>` to capture the 1280×720 / 1440×900 × light/dark
 * screenshot matrix for every surface.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import type { Browser, BrowserContext, Page } from '@playwright/test'

const GITHUB_MOCK_ENV = 'KOVO_UI_W2B_GITHUB_MOCK'
const THIS_FILE = fileURLToPath(import.meta.url)
const ORGS = ['acme-platform', 'acme-payments', 'acme-mobile-apps', 'acme-security-tooling'] as const

// ---------------------------------------------------------------------------
// Preload mode: hermetic GitHub REST mock inside the spawned Kovo server.
// ---------------------------------------------------------------------------

function installGithubFetchMock(): void {
  const original = globalThis.fetch
  const repoFor = (org: string, i: number) => ({
    full_name: `${org}/service-${String(i).padStart(2, '0')}${i === 3 ? '-with-a-considerably-longer-name' : ''}`,
    private: i % 3 !== 0,
    default_branch: i === 4 ? 'release/2026-11-hotfix' : 'main',
    updated_at: new Date(Date.UTC(2026, 10, 25 - i)).toISOString(),
    description: i === 1 ? 'Checkout, session, and storefront API services.' : null,
  })
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    if (url.hostname !== 'api.github.com') return original(input, init)
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })
    if (url.pathname === '/user') return json({ login: 'kovo-qa' })
    // Empty /user/repos makes the connector fall back to the installation listing.
    if (url.pathname === '/user/repos') return json([])
    if (url.pathname === '/user/installations') {
      return json({
        total_count: ORGS.length,
        installations: ORGS.map((org, index) => ({
          id: 1000 + index,
          account: { login: org, type: 'Organization' },
          repository_selection: index === 0 ? 'all' : 'selected',
          html_url: `https://github.com/organizations/${org}/settings/installations/${1000 + index}`,
        })),
      })
    }
    const match = /^\/user\/installations\/(\d+)\/repositories$/.exec(url.pathname)
    if (match) {
      const org = ORGS[Number(match[1]) - 1000]
      const page = Number(url.searchParams.get('page') ?? '1')
      if (!org || page > 1) return json({ repositories: [] })
      return json({ repositories: Array.from({ length: 9 }, (_, i) => repoFor(org, i + 1)) })
    }
    return json({ message: 'Not Found' }, 404)
  }) as typeof fetch
}

// ---------------------------------------------------------------------------
// Behavioural unit tests (pure helpers; no source-text assertions)
// ---------------------------------------------------------------------------

function defineUnitSuite(): void {
  describe('[U12] origin chip editor helpers', () => {
    it('validates http(s) origins with a real host and normalises bare hosts', async () => {
      const { normalizeOrigin } = await import('../src/components/project/OriginChipInput.tsx')
      assert.equal(normalizeOrigin('https://app.example.com').valid, true)
      assert.equal(normalizeOrigin('app.example.com').valid, true)
      assert.equal(normalizeOrigin('http://localhost:3000').valid, true)
      assert.equal(normalizeOrigin('ftp://files.example.com').valid, false)
      assert.equal(normalizeOrigin('not a url').valid, false)
      assert.equal(normalizeOrigin('intranet').valid, false, 'single-label hosts are typos, not origins')
      assert.equal(normalizeOrigin('HTTPS://App.Example.com/').key, normalizeOrigin('app.example.com').key)
    })

    it('tokenizes on new lines, commas, and spaces without shredding phrases', async () => {
      const { tokenizeOrigins } = await import('../src/components/project/OriginChipInput.tsx')
      assert.deepEqual(tokenizeOrigins('a.example.com\nb.example.com, c.example.com'), ['a.example.com', 'b.example.com', 'c.example.com'])
      assert.deepEqual(tokenizeOrigins('a.example.com b.example.com'), ['a.example.com', 'b.example.com'])
      assert.deepEqual(tokenizeOrigins('https://ok.example.com\nnot a url'), ['https://ok.example.com', 'not a url'])
      assert.deepEqual(tokenizeOrigins(' , \n '), [])
    })

    it('dedupes, commits drafts on separators, and keeps text mode in sync', async () => {
      const m = await import('../src/components/project/OriginChipInput.tsx')
      assert.deepEqual(m.mergeOrigins(['https://a.example.com'], ['A.EXAMPLE.COM', 'b.example.com']), ['https://a.example.com', 'b.example.com'])
      // Comma / new line commit every segment; a typed space commits only a valid origin.
      assert.deepEqual(m.applyOriginDraft([], 'x.example.com,'), { values: ['x.example.com'], draft: '' })
      assert.deepEqual(m.applyOriginDraft(['x.example.com'], 'y.example.com\nnope'), { values: ['x.example.com', 'y.example.com', 'nope'], draft: '' })
      assert.deepEqual(m.applyOriginDraft([], 'z.example.com '), { values: ['z.example.com'], draft: '' })
      assert.deepEqual(m.applyOriginDraft([], 'not '), { values: [], draft: 'not ' })
      assert.deepEqual(m.commitOriginDraft(['a.example.com'], 'a.example.com'), ['a.example.com'])
      const summary = m.summarizeOrigins(['a.example.com', 'bad host', 'b.example.com'])
      assert.deepEqual(summary, { total: 3, invalid: 1, invalidTokens: ['bad host'] })
      assert.equal(m.formatOriginCount(summary.total, summary.invalid), '3 origins · 1 invalid')
      assert.equal(m.formatOriginCount(1, 0), '1 origin')
      // Text-mode round trip: chips → text → chips is lossless for deduped lists.
      const chips = ['https://a.example.com', 'b.example.com', 'bad host']
      assert.deepEqual(m.mergeOrigins([], m.tokenizeOrigins(chips.join('\n'))), chips)
    })

    it('renders valid/invalid chips, the live count, and the inline error', async () => {
      const { createElement } = await import('react')
      const { renderToStaticMarkup } = await import('react-dom/server')
      const { OriginChipInput } = await import('../src/components/project/OriginChipInput.tsx')
      const html = renderToStaticMarkup(createElement(OriginChipInput, {
        values: ['https://a.example.com', 'not a url'],
        onChange: () => {},
      }))
      assert.ok(html.includes('2 origins · 1 invalid'))
      assert.equal((html.match(/data-slot="origin-chip"/g) ?? []).length, 2)
      assert.ok(html.includes('data-valid="false"'))
      assert.ok(html.includes('aria-label="Remove not a url"'))
      assert.ok(html.includes('Not a valid host or origin: not a url'))
      assert.ok(html.includes('Edit as text'))
    })
  })

  describe('[U12] persona stepper, New run combobox, project draft', () => {
    it('steps clamp, labels follow the method, and browser saves are gated until captured', async () => {
      const m = await import('../src/components/project/PersonaFormModal.tsx')
      assert.equal(m.stepPersonaFlow(1, 1), 2)
      assert.equal(m.stepPersonaFlow(3, 1), 3)
      assert.equal(m.stepPersonaFlow(1, -1), 1)
      assert.deepEqual(m.personaStepLabels('browser_session'), ['Account', 'Method', 'Capture'])
      assert.deepEqual(m.personaStepLabels('header_cookie'), ['Account', 'Method', 'Credentials'])
      const base = { hasCapturedToken: false, hasStorageState: false, keepsExistingSession: false }
      assert.equal(m.personaSaveGate({ mode: 'browser_session', ...base }).allowed, false)
      assert.match(m.personaSaveGate({ mode: 'browser_session', ...base }).reason, /Capture a browser session/)
      assert.equal(m.personaSaveGate({ mode: 'browser_session', ...base, hasCapturedToken: true }).allowed, true)
      assert.equal(m.personaSaveGate({ mode: 'browser_session', ...base, hasStorageState: true }).allowed, true)
      assert.equal(m.personaSaveGate({ mode: 'browser_session', ...base, keepsExistingSession: true }).allowed, true, 'editing keeps the captured session')
      assert.equal(m.personaSaveGate({ mode: 'header_cookie', ...base }).allowed, true)
      assert.equal(m.parseStoredAuthMode('automated_login'), 'automated_login')
      assert.equal(m.parseStoredAuthMode('<script>'), null)
      assert.equal(m.parseStoredAuthMode(null), null)
    })

    it('filters accounts and caps the chip row with a +N overflow', async () => {
      const m = await import('../src/components/project/ProjectNewRunSheet.tsx')
      const personas = Array.from({ length: 12 }, (_, i) => ({
        id: `p${i}`,
        handle: `user-${String.fromCharCode(97 + i)}`,
        roleLabel: i % 2 ? 'Admin' : 'Member',
        tenantRef: i < 6 ? 'acme' : 'globex',
      }))
      assert.equal(m.filterAccounts(personas, '').length, 12)
      assert.deepEqual(m.filterAccounts(personas, 'USER-C').map(p => p.id), ['p2'])
      assert.equal(m.filterAccounts(personas, 'globex').length, 6)
      assert.equal(m.filterAccounts(personas, 'admin').length, 6)
      assert.equal(m.filterAccounts(personas, 'zzz').length, 0)
      const twelve = m.summarizeAccountChips(personas)
      assert.equal(twelve.visible.length, m.MAX_VISIBLE_ACCOUNT_CHIPS)
      assert.equal(twelve.overflow, 12 - m.MAX_VISIBLE_ACCOUNT_CHIPS)
      assert.deepEqual(m.summarizeAccountChips(personas.slice(0, 6)), { visible: personas.slice(0, 6), overflow: 0 }, 'no lone "+1" pill')
      assert.deepEqual(m.summarizeAccountChips([]), { visible: [], overflow: 0 })
      assert.equal(m.formatAccountSelection(4, 12), '4 of 12 selected')
    })

    it('persists only non-secret draft fields and rejects malformed drafts', async () => {
      const m = await import('../src/components/project/CreateProjectGithubBlock.tsx')
      const raw = m.serializeProjectDraft({ name: 'Acme Web', sites: 'https://acme.example', token: 'ghp_secret' } as never)
      assert.ok(raw)
      assert.deepEqual(JSON.parse(raw), { name: 'Acme Web', sites: 'https://acme.example' })
      assert.equal(m.serializeProjectDraft({ name: ' ', sites: '' }), null)
      assert.deepEqual(m.parseProjectDraft(raw), { name: 'Acme Web', sites: 'https://acme.example' })
      assert.equal(m.parseProjectDraft('{"name":1,"sites":"x"}'), null)
      assert.equal(m.parseProjectDraft('not json'), null)
      assert.equal(m.parseProjectDraft(null), null)
    })
  })

  describe('[U15] inventory table + repo sheet helpers', () => {
    it('groups hosts by scope and keeps hidden selections on select-all', async () => {
      const m = await import('../src/components/project/ProjectInventoryTab.tsx')
      const assets = [
        { id: 'a', origin: 'https://a.example.com', thirdParty: false },
        { id: 'b', origin: 'https://b.example.com', thirdParty: false },
        { id: 'c', origin: 'https://c.example.com', thirdParty: true },
        { id: 'd', origin: 'https://d.example.com', thirdParty: false },
      ]
      const groups = m.groupInventoryAssets(assets, new Set(['https://a.example.com']))
      assert.deepEqual(groups.approved.map(a => a.id), ['a'])
      assert.deepEqual(groups.needsApproval.map(a => a.id), ['b', 'c', 'd'])
      assert.deepEqual(groups.unapprovedFirstParty.map(a => a.id), ['b', 'd'])

      const hiddenSelected = new Set(['z'])
      const selected = m.toggleVisibleSelection(hiddenSelected, ['a', 'b'], true)
      assert.deepEqual([...selected].sort(), ['a', 'b', 'z'])
      assert.deepEqual(m.visibleSelectionState(['a', 'b'], selected), { selectedVisible: 2, all: true, some: false })
      assert.deepEqual(m.visibleSelectionState(['a', 'b', 'c'], selected), { selectedVisible: 2, all: false, some: true })
      assert.deepEqual([...m.toggleVisibleSelection(selected, ['a', 'b'], false)], ['z'])
      assert.deepEqual(m.visibleSelectionState([], new Set()), { selectedVisible: 0, all: false, some: false })
      assert.equal(m.formatAssetSource('phase0_subdomain_discovery'), 'Subdomain discovery')
      assert.equal(m.formatAssetSource('DNS export'), 'DNS export')
      assert.equal(m.formatAssetSource(null), 'Unknown')
    })

    it('summarises GitHub installations', async () => {
      const m = await import('../src/components/project/ProjectSourcesTab.tsx')
      assert.equal(m.formatInstallationSummary(1), 'Installed on 1 account')
      assert.equal(m.formatInstallationSummary(4), 'Installed on 4 accounts')
    })
  })
}

// ---------------------------------------------------------------------------
// Playwright harness
// ---------------------------------------------------------------------------

const HARDENED_FLAGS = [
  '--disable-proto=delete',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
]
const SYSTEM_CHROMIUM = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  for (const modName of ['@playwright/test', 'playwright-core'] as const) {
    let pw: PlaywrightModule | null = null
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') pw = loaded as PlaywrightModule
    } catch {
      continue
    }
    if (!pw) continue
    let bundled = ''
    try { bundled = pw.chromium.executablePath() } catch { bundled = '' }
    if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
    const system = SYSTEM_CHROMIUM.find(candidate => existsSync(candidate))
    if (system) return { pw, executablePath: system }
  }
  return null
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate an ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

interface KovoServer {
  origin: string
  cookies: { name: string; value: string }[]
  stop(): Promise<void>
}

async function startKovo(dataDir: string, extraEnv: Record<string, string>): Promise<KovoServer> {
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(process.execPath, [...HARDENED_FLAGS, '--import', THIS_FILE, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), KOVO_DATA_DIR: dataDir, KOVO_OFFLINE: '', KOVO_PUBLIC_ORIGIN: '', [GITHUB_MOCK_ENV]: '1', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', chunk => { output += String(chunk) })
  child.stderr?.on('data', chunk => { output += String(chunk) })
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      if (await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  let healthy = false
  for (let attempt = 0; attempt < 200 && child.exitCode === null; attempt += 1) {
    try {
      if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })).ok) { healthy = true; break }
    } catch { /* not bound yet */ }
    await delay(70)
  }
  if (!healthy) { await stop(); throw new Error(`serve.ts failed to start on ${origin}.\n${output.slice(-2000)}`) }
  let secret = ''
  for (let i = 0; i < 40 && !secret; i += 1) {
    try { secret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
  }
  if (!secret) { await stop(); throw new Error('bootstrap secret was not written') }
  const res = await fetch(`${origin}/?bootstrap=${encodeURIComponent(secret)}`, { redirect: 'manual' })
  const cookies = res.headers.getSetCookie().map(raw => {
    const [pair] = raw.split(';')
    const eq = pair!.indexOf('=')
    return { name: pair!.slice(0, eq).trim(), value: pair!.slice(eq + 1).trim() }
  })
  assert.ok(cookies.length > 0, 'bootstrap must set a session cookie')
  return { origin, cookies, stop }
}

interface Seed {
  projectId: string
  firstPartyIds: string[]
}

const SEED_ORIGINS = ['https://acme.example.com', 'https://api.acme.example.com', 'https://auth.acme.example.com', 'https://admin.acme.example.com']
const PERSONA_COUNT = 12

async function seedWorkspace(dataDir: string): Promise<Seed> {
  const { Store } = await import('../src/server/store.ts')
  const { createProjectPersona } = await import('../src/server/persona-vault.ts')
  const s = new Store(dataDir)
  try {
    const project = s.createProject({
      requestId: randomUUID(), name: 'Acme Storefront', seeds: SEED_ORIGINS, environment: 'public', includeSubdomains: false,
    } as never)
    for (let i = 0; i < PERSONA_COUNT; i += 1) {
      const letter = String.fromCharCode(65 + i)
      createProjectPersona(s, {
        requestId: randomUUID(), projectId: project.id, handle: `user-${letter.toLowerCase()}`,
        roleLabel: `User ${letter}`, originAllowlist: [SEED_ORIGINS[0]!], authKind: 'cookie',
        secret: `session=qa-fixture-${letter}`, canaryMarkers: [],
      } as never)
    }
    const firstPartyIds: string[] = []
    const add = s.client.prepare(
      `INSERT INTO project_assets (id, project_id, origin, source, third_party, include_subdomains, prepared, dns_source, access_policy)
       VALUES (?, ?, ?, ?, ?, 0, NULL, ?, NULL)`,
    )
    const firstParty = ['billing', 'cdn', 'console', 'docs', 'files', 'gateway', 'graphql', 'metrics', 'status', 'webhooks']
    for (const sub of firstParty) {
      const id = randomUUID()
      firstPartyIds.push(id)
      add.run(id, project.id, `https://${sub}.acme.example.com`, 'phase0_subdomain_discovery', 0, JSON.stringify({ zone: 'acme.example.com' }))
    }
    for (const [sub, cname] of [['blog', 'acme.ghost.io'], ['help', 'acme.zendesk.com'], ['shop', 'shops.myshopify.com']] as const) {
      add.run(randomUUID(), project.id, `https://${sub}.acme.example.com`, 'phase0_subdomain_discovery', 1, JSON.stringify({ zone: 'acme.example.com', externalAliases: [cname] }))
    }
    return { projectId: project.id, firstPartyIds }
  } finally {
    s.close()
  }
}

type Theme = 'light' | 'dark'
interface Viewport { width: number; height: number; label: string }
const VIEWPORTS: readonly Viewport[] = [
  { width: 1280, height: 720, label: '1280x720' },
  { width: 1440, height: 900, label: '1440x900' },
]
const THEMES: readonly Theme[] = ['light', 'dark']
const SHOT_DIR = process.env.KOVO_UI_SHOTS_DIR?.trim() || ''

async function forEachCombo(fn: (vp: Viewport, theme: Theme) => Promise<void>): Promise<void> {
  await Promise.all(VIEWPORTS.flatMap(vp => THEMES.map(theme => fn(vp, theme))))
}

async function shot(page: Page, name: string, vp: Viewport, theme: Theme): Promise<void> {
  if (!SHOT_DIR) return
  mkdirSync(SHOT_DIR, { recursive: true })
  await delay(260) // let enter transitions settle
  await page.screenshot({ path: join(SHOT_DIR, `${name}-${vp.label}-${theme}.png`) })
}

/**
 * Geometry probe, shipped as plain JS source so the bundler's keepNames helper
 * never leaks into the page. Reports horizontal overflow on the container and
 * its scroll regions, clipped buttons/chips, overlapping sibling controls, and
 * raw "null"/"undefined" copy.
 */
const GEOMETRY_PROBE = String.raw`(selector) => {
  const root = document.querySelector(selector)
  if (!root) return { missing: true, overflow: [], clipped: [], overlaps: [], rawNullish: [] }
  const visible = el => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden' }
  const overflow = []
  for (const el of [root, ...root.querySelectorAll('*')]) {
    if (!visible(el)) continue
    const style = getComputedStyle(el)
    const scrolls = el === root || style.overflowX === 'auto' || style.overflowX === 'scroll'
    if (scrolls && el.scrollWidth > el.clientWidth + 1) overflow.push(el.tagName.toLowerCase() + '[' + (el.getAttribute('data-slot') || '') + '] ' + el.scrollWidth + '>' + el.clientWidth)
  }
  const edge = root.getBoundingClientRect().right + 1
  for (const el of root.querySelectorAll('*')) {
    if (visible(el) && el.getBoundingClientRect().right > edge) overflow.push('spill ' + el.tagName.toLowerCase() + ' "' + (el.textContent || '').trim().slice(0, 24) + '"')
  }
  const clipped = []
  for (const el of root.querySelectorAll('button, [role=radio], [role=switch], [data-slot=origin-chip], [data-slot=persona-pill], [role=option]')) {
    if (visible(el) && el.scrollHeight > el.clientHeight + 2) clipped.push((el.textContent || '').trim().slice(0, 40) + ' ' + el.scrollHeight + '>' + el.clientHeight)
  }
  const controls = [...root.querySelectorAll('button, input, textarea, select, a[href], [role=switch], [role=checkbox]')].filter(visible)
  const overlaps = []
  for (let i = 0; i < controls.length; i += 1) {
    const a = controls[i]
    const ra = a.getBoundingClientRect()
    for (let j = i + 1; j < controls.length; j += 1) {
      const b = controls[j]
      if (a.contains(b) || b.contains(a)) continue
      const rb = b.getBoundingClientRect()
      const x = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left)
      const y = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top)
      if (x > 1 && y > 1) overlaps.push((a.getAttribute('aria-label') || a.textContent || a.tagName).trim().slice(0, 30) + ' × ' + (b.getAttribute('aria-label') || b.textContent || b.tagName).trim().slice(0, 30))
    }
  }
  const text = root.innerText || ''
  const rawNullish = text.match(/\b(null|undefined|NaN)\b/g) || []
  return { missing: false, overflow, clipped, overlaps, rawNullish }
}`

interface GeometryReport { missing: boolean; overflow: string[]; clipped: string[]; overlaps: string[]; rawNullish: string[] }

async function assertCleanGeometry(page: Page, selector: string, ctx: string): Promise<void> {
  const report = await page.evaluate(`(${GEOMETRY_PROBE})(${JSON.stringify(selector)})`) as GeometryReport
  assert.equal(report.missing, false, `${ctx}: ${selector} must exist`)
  assert.deepEqual(report.overflow, [], `${ctx}: zero horizontal overflow in ${selector}`)
  assert.deepEqual(report.clipped, [], `${ctx}: zero clipped buttons/chips in ${selector}`)
  assert.deepEqual(report.overlaps, [], `${ctx}: zero overlapping controls in ${selector}`)
  assert.deepEqual(report.rawNullish, [], `${ctx}: no raw null/undefined copy in ${selector}`)
}

async function assertInViewport(page: Page, locator: ReturnType<Page['locator']>, vp: Viewport, ctx: string): Promise<void> {
  const box = await locator.boundingBox()
  assert.ok(box, `${ctx}: element must be rendered`)
  assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= vp.width + 1 && box.y + box.height <= vp.height + 1,
    `${ctx}: element must sit inside the ${vp.label} viewport above the fold (${JSON.stringify(box)})`)
}

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.evaluate(() => document.fonts?.ready).catch(() => {})
}

// ---------------------------------------------------------------------------
// Playwright suite
// ---------------------------------------------------------------------------

function definePlaywrightSuite(): void {
  describe('Wave 2B Playwright journeys (1280×720 + 1440×900, light + dark)', { timeout: 600_000 }, () => {
    let skipReason: string | null = null
    let browser: Browser | undefined
    let server: KovoServer | undefined
    let seed: Seed | undefined
    const pageErrors: string[] = []

    before(async () => {
      const pwEnv = await loadPlaywright()
      if (!pwEnv) { skipReason = 'Playwright/Chromium unavailable'; return }
      if (!existsSync(resolve('build/server/server.js'))) execFileSync('npm', ['run', 'build'], { stdio: 'pipe' })
      const dataDir = await mkdtemp(join(tmpdir(), 'kovo-ui-w2b-'))
      seed = await seedWorkspace(dataDir)
      const patPath = join(dataDir, 'github-fixture.pat')
      writeFileSync(patPath, `github_pat_${'w'.repeat(60)}\n`, { mode: 0o600 })
      ;[server, browser] = await Promise.all([
        startKovo(dataDir, { KOVO_ALLOW_FIXTURE_GITHUB_PAT: '1', KOVO_GITHUB_FIXTURE_PAT_PATH: patPath }),
        pwEnv.pw.chromium.launch({ headless: true, executablePath: pwEnv.executablePath, args: ['--no-sandbox'] }),
      ])
    })

    after(async () => {
      await browser?.close().catch(() => {})
      await server?.stop().catch(() => {})
    })

    async function withPage<T>(vp: Viewport, theme: Theme, fn: (page: Page) => Promise<T>): Promise<T> {
      const ctx: BrowserContext = await browser!.newContext({ viewport: { width: vp.width, height: vp.height }, colorScheme: theme })
      const url = new URL(server!.origin)
      await ctx.addCookies(server!.cookies.map(c => ({ ...c, domain: url.hostname, path: '/' })))
      await ctx.addInitScript(t => { try { localStorage.setItem('kovo-appearance', t) } catch { /* ignore */ } }, theme)
      const page = await ctx.newPage()
      page.on('pageerror', err => pageErrors.push(`${vp.label}/${theme}: ${err.message}`))
      try {
        return await fn(page)
      } catch (err) {
        if (SHOT_DIR) await page.screenshot({ path: join(SHOT_DIR, `FAIL-${vp.label}-${theme}-${Date.now()}.png`) }).catch(() => {})
        throw err
      } finally {
        await ctx.close()
      }
    }

    async function openProject(page: Page, tab?: string): Promise<void> {
      await page.goto(`${server!.origin}/projects/${seed!.projectId}${tab ? `?tab=${tab}` : ''}`, { waitUntil: 'domcontentloaded' })
      await page.locator('main h1').first().waitFor({ state: 'visible', timeout: 15_000 })
      await settle(page)
    }

    it('[U12] New run: compact mode radios, 12-account combobox with +N chips, Start run above the fold', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page)
        await page.locator('main header').getByRole('button', { name: 'New run' }).click()
        const dialog = page.locator('[data-slot=dialog-content]')
        await dialog.waitFor()
        await delay(200)

        const rows = dialog.getByRole('radiogroup', { name: 'Scan mode' }).getByRole('radio')
        assert.equal(await rows.count(), 3, ctx)
        for (let i = 0; i < 3; i += 1) {
          const box = (await rows.nth(i).boundingBox())!
          assert.ok(box.height >= 38 && box.height <= 48, `${ctx}: mode row ${i} is a compact ~44px row (got ${box.height})`)
        }
        assert.equal(await rows.nth(1).getAttribute('aria-checked'), 'true', `${ctx}: Supervised is the default`)

        assert.equal((await dialog.locator('[data-slot=account-selection-count]').innerText()).trim(), `${PERSONA_COUNT} of ${PERSONA_COUNT} selected`)
        const chips = dialog.locator('[data-slot=persona-pill]')
        assert.equal(await chips.count(), 5, `${ctx}: chip row caps at 5 chips`)
        assert.equal((await dialog.locator('[data-slot=account-chip-overflow]').innerText()).trim(), `+${PERSONA_COUNT - 5}`)
        const chipRow = (await dialog.locator('[data-slot=account-chips]').boundingBox())!
        assert.ok(chipRow.height <= 26 * 2 + 6 + 2, `${ctx}: selected chips stay within two lines (got ${chipRow.height}px)`)

        const submit = dialog.getByRole('button', { name: 'Start run', exact: true })
        await assertInViewport(page, submit, vp, `${ctx} Start run`)
        await assertInViewport(page, dialog.getByLabel('USD Spend Cap'), vp, `${ctx} budget`)
        const bodyScroll = await dialog.locator('[data-slot=dialog-body]').evaluate(el => el.scrollHeight - el.clientHeight)
        assert.ok(bodyScroll <= 2, `${ctx}: the whole New run form fits without scrolling (overflow ${bodyScroll}px)`)
        await assertCleanGeometry(page, '[data-slot=dialog-content]', ctx)
        await shot(page, 'newrun', vp, theme)

        // Searchable combobox: filter, toggle, and dismiss without closing the sheet.
        await dialog.locator('[data-slot=account-combobox-trigger]').click()
        const search = page.getByRole('combobox', { name: 'Search test accounts' })
        await search.waitFor()
        const listbox = page.getByRole('listbox', { name: 'Test accounts' })
        assert.equal(await listbox.getByRole('option').count(), PERSONA_COUNT)
        await search.fill('user-c')
        assert.equal(await listbox.getByRole('option').count(), 1, `${ctx}: search filters the listbox`)
        await listbox.getByRole('option').first().click()
        assert.equal(await listbox.getByRole('option').first().getAttribute('aria-selected'), 'false')
        assert.equal((await dialog.locator('[data-slot=account-selection-count]').innerText()).trim(), `${PERSONA_COUNT - 1} of ${PERSONA_COUNT} selected`)
        await assertCleanGeometry(page, '[data-slot=account-combobox-popup]', `${ctx} popup`)
        await page.keyboard.press('Escape')
        await listbox.waitFor({ state: 'hidden' })
        assert.ok(await dialog.isVisible(), `${ctx}: Escape closes only the combobox`)

        await dialog.getByRole('button', { name: 'Clear', exact: true }).click()
        assert.equal((await dialog.locator('[data-slot=account-selection-count]').innerText()).trim(), `0 of ${PERSONA_COUNT} selected`)
        await dialog.getByRole('button', { name: 'Select all', exact: true }).click()
        assert.equal(await chips.count(), 5)
      }))
    })

    it('[U12] Edit project: origin chip editor validates, dedupes, removes, and syncs with text mode', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page)
        await page.getByRole('button', { name: 'Project actions' }).click()
        await page.getByRole('menuitem', { name: 'Edit project' }).click()
        const dialog = page.locator('[data-slot=dialog-content]')
        await dialog.waitFor()
        await delay(200)
        const chips = dialog.locator('[data-slot=origin-chip]')
        const count = dialog.locator('[data-slot=seed-count]')
        const save = dialog.getByRole('button', { name: 'Save changes' })
        assert.equal(await chips.count(), SEED_ORIGINS.length, ctx)
        assert.equal((await count.innerText()).trim(), `${SEED_ORIGINS.length} origins`)
        assert.match(await dialog.innerText(), /Seed origins\s*·\s*4 origins/)

        const draft = dialog.locator('textarea[name=seeds]')
        await draft.click()
        await draft.pressSequentially('https://shop.acme.example.com,')
        await draft.pressSequentially('ACME.EXAMPLE.COM')
        await page.keyboard.press('Enter')
        assert.equal(await chips.count(), SEED_ORIGINS.length + 1, `${ctx}: comma commits, case/scheme duplicate is dropped`)
        await draft.fill('https://status.acme.example.com\nnot a url')
        assert.equal((await count.innerText()).trim(), '7 origins · 1 invalid', `${ctx}: paste splits into chips with live validation`)
        assert.equal(await dialog.locator('[data-slot=origin-chip][data-valid=false]').count(), 1)
        assert.match(await dialog.locator('[data-slot=seed-invalid]').innerText(), /not a url$/)
        assert.ok(await save.isDisabled(), `${ctx}: Save disabled with an invalid origin`)
        await assertCleanGeometry(page, '[data-slot=dialog-content]', ctx)
        await shot(page, 'editproject-chips', vp, theme)

        await dialog.getByRole('button', { name: 'Remove not a url' }).click()
        assert.equal((await count.innerText()).trim(), '6 origins')
        assert.ok(await save.isEnabled(), `${ctx}: Save re-enables once every chip is valid`)

        // Backspace on an empty draft pulls the last chip back for editing.
        await draft.focus()
        await page.keyboard.press('Backspace')
        assert.equal(await chips.count(), 5)
        assert.equal(await draft.inputValue(), 'https://status.acme.example.com')
        await page.keyboard.press('Enter')
        assert.equal(await chips.count(), 6)

        await dialog.getByRole('button', { name: 'Edit as text' }).click()
        const text = dialog.locator('textarea[name=seeds]')
        assert.equal((await text.inputValue()).split('\n').length, 6, `${ctx}: text mode lists every origin`)
        await text.fill(`${await text.inputValue()}\nbad host`)
        assert.equal((await count.innerText()).trim(), '7 origins · 1 invalid', `${ctx}: counts stay in sync in text mode`)
        await dialog.getByRole('button', { name: 'Edit as chips' }).click()
        assert.equal(await dialog.locator('[data-slot=origin-chip][data-valid=false]').count(), 1)

        await dialog.locator('input[name=name]').fill('')
        assert.ok(await dialog.getByText('Name is required').isVisible())
        assert.equal(await dialog.locator('input[name=name]').getAttribute('placeholder'), 'e.g. Acme Web')
        assert.ok(await save.isDisabled())
        await assertInViewport(page, save, vp, `${ctx} Save`)
        await dialog.getByRole('button', { name: 'Cancel' }).click()
      }))
    })

    it('[U12] Persona: 3-step Account → Method → Capture flow with gated save', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, 'personas')
        await page.locator('section[aria-label="Test accounts"]').getByRole('button', { name: 'Add test account' }).click()
        const dialog = page.locator('[data-slot=dialog-content]')
        await dialog.waitFor()
        await delay(220)
        const stepper = dialog.getByRole('navigation', { name: 'Test account setup steps' })
        const current = stepper.locator('[aria-current=step]')
        assert.match(await current.innerText(), /1\s*Account/, ctx)
        assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('name')), 'roleLabel')
        const top0 = await dialog.evaluate(el => Math.round(el.getBoundingClientRect().top))
        const height0 = await dialog.evaluate(el => Math.round(el.getBoundingClientRect().height))
        const cont = dialog.getByRole('button', { name: 'Continue' })
        assert.equal(await cont.getAttribute('data-variant'), 'default', `${ctx}: Continue is the one filled primary`)
        assert.equal(await dialog.getByRole('button', { name: /Save test account/ }).count(), 0)

        await cont.click()
        assert.match(await current.innerText(), /2\s*Method/)
        const radios = dialog.getByRole('radiogroup', { name: 'Authentication mode' }).getByRole('radio')
        assert.equal(await radios.count(), 3)
        await radios.nth(1).click()
        await dialog.getByRole('button', { name: 'Back' }).click()
        assert.match(await current.innerText(), /1\s*Account/, `${ctx}: Back returns to Account`)
        await cont.click()
        await radios.nth(0).click()
        await page.keyboard.press('Enter')
        assert.match(await current.innerText(), /3\s*Capture/, `${ctx}: Enter advances; browser sessions end on Capture`)

        const signIn = dialog.getByRole('button', { name: 'Sign in with browser' })
        await signIn.waitFor()
        assert.equal(await signIn.getAttribute('data-variant'), 'outline', `${ctx}: capture launcher is not a competing filled primary`)
        const saveBtn = dialog.getByRole('button', { name: 'Save test account' })
        assert.ok(await saveBtn.isDisabled(), `${ctx}: Save gated until a browser session is captured`)
        assert.match(await dialog.locator('[data-slot=persona-footer-note]').innerText(), /Capture a browser session to enable saving/)
        assert.ok(await dialog.locator('[data-slot=capture-required]').isVisible(), `${ctx}: inline helper explains the gate`)
        assert.equal(await dialog.evaluate(el => Math.round(el.getBoundingClientRect().top)), top0, `${ctx}: top-anchored across steps`)
        assert.equal(await dialog.evaluate(el => Math.round(el.getBoundingClientRect().height)), height0, `${ctx}: fixed height across steps`)
        await assertInViewport(page, saveBtn, vp, `${ctx} Save`)
        await assertCleanGeometry(page, '[data-slot=dialog-content]', ctx)
        await shot(page, 'persona-stepper', vp, theme)

        // Completed steps are clickable; credential methods allow the save attempt.
        await stepper.getByRole('button', { name: /Method/ }).click()
        await radios.nth(1).click()
        await cont.click()
        assert.match(await current.innerText(), /3\s*Credentials/)
        assert.ok(await dialog.getByRole('button', { name: 'Save test account' }).isEnabled())
        assert.equal(await page.evaluate(() => localStorage.getItem('kovo:persona-last-auth-method')), 'header_cookie', `${ctx}: last method remembered`)
        await page.keyboard.press('Escape')
      }))
    })

    it('[U15] Inventory: dense table with switches, ⋯ menu, sticky groups, and floating bulk bar', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, 'inventory')
        const section = page.locator('section[aria-label="Project inventory"]')
        const headers = await section.getByRole('columnheader').allTextContents()
        assert.deepEqual(headers.map(h => h.trim()).filter(Boolean), ['Host', 'Source', 'Subdomains', 'In scope', 'Actions'], ctx)
        assert.equal(await section.locator('[data-testid^="inventory-row-"]').count(), 17)
        assert.equal(await page.getByTestId('inventory-batch-bar').count(), 0, `${ctx}: no bulk bar without a selection`)
        const firstId = seed!.firstPartyIds[0]!
        const row = page.getByTestId(`inventory-row-${firstId}`)
        assert.equal(await row.getByRole('switch', { name: 'Include subdomains for billing.acme.example.com' }).getAttribute('aria-checked'), 'false')
        assert.equal(await row.getByRole('switch', { name: 'Approve host billing.acme.example.com in project scope' }).getAttribute('aria-checked'), 'false')
        assert.equal((await row.locator('[data-slot=asset-source]').innerText()).trim(), 'Subdomain discovery')
        const groupHeader = section.locator('[data-slot=inventory-group-header]').last()
        assert.equal(await groupHeader.evaluate(el => getComputedStyle(el).position), 'sticky', `${ctx}: sticky group headers`)
        assert.match(await groupHeader.innerText(), /Needs approval\s*\(13\)/)
        assert.equal((await page.getByTestId('approve-all-first-party').innerText()).trim(), 'Approve all first-party (10)')

        await row.getByRole('button', { name: 'More actions for billing.acme.example.com' }).click()
        const menu = page.getByRole('menu')
        await menu.waitFor()
        assert.deepEqual((await menu.getByRole('menuitem').allInnerTexts()).map(s => s.trim()), ['Edit host…', 'Approve in scope', 'Delete host…'])
        await page.keyboard.press('Escape')
        await menu.waitFor({ state: 'hidden' })

        for (const id of seed!.firstPartyIds.slice(1, 4)) await page.getByTestId(`select-asset-${id}`).click()
        const bar = page.getByTestId('inventory-batch-bar')
        await bar.waitFor()
        await delay(220)
        assert.equal((await page.getByTestId('inventory-batch-count').innerText()).trim(), '3 selected')
        assert.deepEqual(
          (await bar.getByRole('button').allInnerTexts()).map(s => s.replace(/\s+/g, ' ').trim()),
          ['Approve', 'Exclude', 'Delete', 'Clear'],
        )
        await assertInViewport(page, bar, vp, `${ctx} bulk bar`)
        await assertCleanGeometry(page, 'section[aria-label="Project inventory"]', ctx)
        await shot(page, 'inventory-bulk', vp, theme)
        await page.getByTestId('batch-clear-selection').click()
        await bar.waitFor({ state: 'hidden' })
      }))

      // Mutating flows run once (the combos above share one project).
      await withPage(VIEWPORTS[0]!, 'light', async page => {
        await openProject(page, 'inventory')
        const notice = page.locator('section[aria-label="Project inventory"] [role=status]').first()
        const sw = page.getByRole('switch', { name: 'Include subdomains for billing.acme.example.com' })
        await sw.click()
        await page.getByText('Enabled subdomain discovery for billing.acme.example.com.').waitFor()
        assert.equal(await sw.getAttribute('aria-checked'), 'true')

        for (const id of seed!.firstPartyIds.slice(1, 4)) await page.getByTestId(`select-asset-${id}`).click()
        await page.getByTestId('batch-approve-selected').click()
        await page.getByText('Approved 3 hosts in project scope.').waitFor()
        assert.equal(await page.getByTestId('inventory-batch-bar').count(), 0)
        assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*7/)

        for (const id of seed!.firstPartyIds.slice(1, 3)) await page.getByTestId(`select-asset-${id}`).click()
        await page.getByTestId('batch-unapprove-selected').click()
        await page.getByText('Unapproved 2 hosts from project scope.').waitFor()
        assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*5/)
        assert.match(await notice.innerText(), /Unapproved 2 hosts/)

        const scopeSwitch = page.getByRole('switch', { name: 'Approve host status.acme.example.com in project scope' })
        await scopeSwitch.click()
        await page.getByText('Approved status.acme.example.com in project scope.').waitFor()
        assert.equal(await page.getByRole('switch', { name: 'Remove host status.acme.example.com from project scope' }).getAttribute('aria-checked'), 'true')
      })
    })

    it('[U15] Repo discovery opens in a right sheet with sticky search, org headers, and selection tray', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, 'sources')
        await page.locator('main').getByRole('button', { name: /Discover repositories|Discover & sync repos/ }).first().click()
        const sheet = page.locator('.pw-repo-sheet')
        await sheet.getByRole('group', { name: 'Accessible GitHub repositories' }).waitFor({ timeout: 15_000 })
        await settle(page)
        await delay(250)
        const box = (await sheet.boundingBox())!
        assert.equal(Math.round(box.width), Math.min(640, vp.width), `${ctx}: sheet width is min(640px, 100vw)`)
        assert.equal(Math.round(box.height), vp.height, `${ctx}: full-height sheet`)
        assert.equal(Math.round(box.x + box.width), vp.width, `${ctx}: anchored to the right edge`)

        const pill = sheet.locator('[data-slot=installations-pill]')
        assert.match(await pill.innerText(), /Installed on 4 accounts/)
        assert.equal(await pill.getAttribute('aria-expanded'), 'false')
        assert.equal(await sheet.getByRole('region', { name: 'Installed GitHub accounts and organizations' }).count(), 0)
        await pill.click()
        await sheet.getByRole('region', { name: 'Installed GitHub accounts and organizations' }).waitFor()
        await pill.click()

        assert.equal(await sheet.locator('[data-slot=org-header]').count(), ORGS.length, `${ctx}: 4 org groups`)
        const collapsed = sheet.locator('[data-slot=org-header] button[aria-expanded=false]')
        while (await collapsed.count() > 0) await collapsed.first().click()
        assert.equal(await sheet.getByRole('checkbox', { name: /^Select repository / }).count(), 36, `${ctx}: 36 repos listed`)

        const list = sheet.locator('[data-slot=repo-picker-list]')
        const search = sheet.locator('input[type=search]')
        const searchTop = (await search.boundingBox())!.y
        const listTop = (await list.boundingBox())!.y
        await list.evaluate(el => { el.scrollTop = 700 })
        await delay(120)
        assert.equal((await search.boundingBox())!.y, searchTop, `${ctx}: search bar stays pinned`)
        const stuck = await list.evaluate(el => {
          const top = el.getBoundingClientRect().top
          return [...el.querySelectorAll('[data-slot=org-header]')].some(h => Math.abs(h.getBoundingClientRect().top - top) < 1.5)
        })
        assert.ok(stuck, `${ctx}: an org header sticks to the list top (list top ${listTop})`)
        const nested = await sheet.evaluate(root => [...root.querySelectorAll('*')].filter(el => {
          const style = getComputedStyle(el)
          return (style.overflowY === 'auto' || style.overflowY === 'scroll') && el.scrollHeight > el.clientHeight + 1
        }).length)
        assert.equal(nested, 1, `${ctx}: exactly one scroll region (no nested double scrollbars)`)

        const boxes = sheet.getByRole('checkbox', { name: /^Select repository / })
        await list.evaluate(el => { el.scrollTop = 0 })
        for (let i = 0; i < 4; i += 1) await boxes.nth(i).click()
        const tray = sheet.locator('[data-slot=repo-selection-tray]')
        assert.match(await sheet.locator('[data-slot=repo-selection-count]').innerText(), /^4 selected of 36$/)
        const sync = tray.getByRole('button', { name: 'Sync', exact: true })
        assert.ok(await sync.isEnabled())
        await assertInViewport(page, tray, vp, `${ctx} selection tray`)
        await assertInViewport(page, sync, vp, `${ctx} Sync`)
        assert.equal(await sheet.getByRole('button', { name: /^Refresh/ }).count(), 1)
        await assertCleanGeometry(page, '.pw-repo-sheet', ctx)
        await shot(page, 'repo-discovery', vp, theme)

        await page.keyboard.press('Escape')
        await sheet.waitFor({ state: 'hidden' })
      }))
    })

    it('no uncaught page errors', t => {
      if (skipReason) return t.skip(skipReason)
      assert.deepEqual(pageErrors, [])
    })
  })
}

// Entry point (kept last so every module-level constant above is initialised).
if (process.env[GITHUB_MOCK_ENV] === '1') {
  installGithubFetchMock()
} else {
  defineUnitSuite()
  definePlaywrightSuite()
}
