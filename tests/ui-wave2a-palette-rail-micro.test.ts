/**
 * Desktop Bucket B Wave 2A: [U19] command palette combobox + fallbacks, [U20]
 * warm-up tooltip group + mouse-only hover highlight, [U14] projects index /
 * rail scanability, and the zero-specificity `:where(a)` reset.
 *
 * Pure helpers are unit-tested directly; everything else is behavioural against
 * the freshly built bundle served by a hermetic `scripts/serve.ts` (temp
 * KOVO_DATA_DIR seeded through the real Store API). Desktop only: 1280×720 and
 * 1440×900 in light and dark.
 *
 * Set `KOVO_UI_W2A_SCREENSHOT_DIR=<dir>` to also capture the screenshot matrix.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test'
import {
  buildRailFeed,
  formatElapsed,
  middleTruncate,
  projectDisambiguators,
  RAIL_FEED_LIMIT,
} from '../src/components/shell/AppShell.tsx'
import {
  groupPaletteItems,
  paletteAnnouncement,
  paletteOptionId,
  PALETTE_LIST_ID,
} from '../src/components/shell/GlobalPalette.tsx'
import {
  hoverHighlightStyle,
  isMouseHover,
  SYNTHETIC_MOUSE_AFTER_TOUCH_MS,
  TOOLTIP_DELAY_MS,
  TOOLTIP_WARM_TIMEOUT_MS,
} from '../src/components/ui/tooltip.tsx'

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('[U14] rail feed + disambiguation helpers', () => {
  const run = (id: string, projectId: string, status = 'complete', projectName = `P-${projectId}`) =>
    ({ id, projectId, projectName, status })

  it('pins live runs first, groups the rest by project once, caps at the feed limit', () => {
    const runs = [
      run('r1', 'a'), run('r2', 'b', 'running'), run('r3', 'a'), run('r4', 'c'),
      run('r5', 'b'), run('r6', 'a', 'queued'), run('r7', 'c'), run('r8', 'd'),
      run('r9', 'd'), run('r10', 'a'), run('r11', 'e'),
    ]
    const feed = buildRailFeed(runs)
    assert.equal(RAIL_FEED_LIMIT, 8)
    assert.deepEqual(feed.live.map(r => r.id), ['r2', 'r6'])
    assert.deepEqual(feed.groups.map(g => g.projectId), ['a', 'c', 'b', 'd'])
    assert.deepEqual(feed.groups.map(g => g.runs.map(r => r.id)), [['r1', 'r3'], ['r4', 'r7'], ['r5'], ['r8']])
    const shown = feed.live.length + feed.groups.reduce((n, g) => n + g.runs.length, 0)
    assert.equal(shown, 8)
    assert.equal(feed.hiddenCount, runs.length - 8)
    assert.equal(buildRailFeed(runs.slice(0, 3)).hiddenCount, 0)
    assert.deepEqual(buildRailFeed([]), { live: [], groups: [], hiddenCount: 0 })
  })

  it('disambiguates namesakes by unique host, else short id; unique names stay bare', () => {
    const map = projectDisambiguators([
      { id: 'aaaaaa11-0000', name: 'Shopflow', hosts: ['shop-a.example.com'] },
      { id: 'bbbbbb22-0000', name: 'shopflow ', hosts: ['shop-b.example.com:8443'] },
      { id: 'cccccc33-0000', name: 'Shopflow', hosts: ['shop-a.example.com'] },
      { id: 'dddddd44-0000', name: 'Northwind', hosts: ['nw.example.com'] },
      { id: 'eeeeee55-0000', name: 'Bare', hosts: [] },
      { id: 'ffffff66-0000', name: 'Bare' },
    ])
    assert.equal(map.get('bbbbbb22-0000'), 'shop-b.example.com:8443')
    assert.equal(map.get('aaaaaa11-0000'), '#aaaaaa')
    assert.equal(map.get('cccccc33-0000'), '#cccccc')
    assert.equal(map.get('eeeeee55-0000'), '#eeeeee')
    assert.equal(map.get('ffffff66-0000'), '#ffffff')
    assert.equal(map.has('dddddd44-0000'), false)
    for (const value of map.values()) assert.doesNotMatch(value, /undefined|null/)
  })

  it('middle-truncates so both ends survive, and formats tabular elapsed time', () => {
    assert.equal(middleTruncate('short.example.com', 28), 'short.example.com')
    const cut = middleTruncate('shopflow-storefront-regression-12.example.com:8443', 24)
    assert.equal(cut.length, 24)
    assert.ok(cut.startsWith('shopflow-st') && cut.endsWith('.com:8443') && cut.includes('…'), cut)
    assert.equal(formatElapsed(10_000), 'now')
    assert.equal(formatElapsed(4 * 60_000 + 5_000), '4m')
    assert.equal(formatElapsed(65 * 60_000), '1h 05m')
    assert.equal(formatElapsed(51 * 3_600_000), '2d 3h')
    assert.equal(formatElapsed(Number.NaN), 'now')
  })
})

describe('[U19] palette grouping helpers', () => {
  it('groups contiguous sections with flat indices and stable header ids', () => {
    const items = [
      { id: 'nav.projects', section: 'Navigation' }, { id: 'nav.settings', section: 'Navigation' },
      { id: 'proj.1', section: 'Projects' }, { id: 'run.1', section: 'Recent runs' },
    ]
    const groups = groupPaletteItems(items)
    assert.deepEqual(groups.map(g => [g.section, g.headerId, g.entries.map(e => e.index)]), [
      ['Navigation', 'gp-group-navigation', [0, 1]],
      ['Projects', 'gp-group-projects', [2]],
      ['Recent runs', 'gp-group-recent-runs', [3]],
    ])
    assert.equal(PALETTE_LIST_ID, 'gp-list')
    assert.equal(paletteOptionId('nav.projects'), 'gp-opt-nav.projects')
  })

  it('announces result counts and the no-match fallback count', () => {
    assert.equal(paletteAnnouncement('', 9, 0), '9 results')
    assert.equal(paletteAnnouncement('proj', 1, 0), '1 result')
    assert.equal(paletteAnnouncement('zzz', 0, 3), 'No exact matches, 3 fallback actions')
  })
})

describe('[U20] pointer-intent helpers', () => {
  it('only a real mouse (not the emulated mouse right after a tap) drives hover', () => {
    assert.equal(TOOLTIP_DELAY_MS, 500)
    assert.equal(TOOLTIP_WARM_TIMEOUT_MS, 300)
    assert.equal(isMouseHover('mouse', 5_000, Number.NEGATIVE_INFINITY), true)
    assert.equal(isMouseHover('touch', 5_000, Number.NEGATIVE_INFINITY), false)
    assert.equal(isMouseHover('pen', 5_000, Number.NEGATIVE_INFINITY), false)
    assert.equal(isMouseHover('mouse', 1_050, 1_000), false)
    assert.equal(isMouseHover('mouse', 1_000 + SYNTHETIC_MOUSE_AFTER_TOUCH_MS + 1, 1_000), true)
  })

  it('positions the highlight with a composited translate3d, never top/left', () => {
    const style = hoverHighlightStyle({ y: 62, height: 30 })
    assert.deepEqual(style, { height: '30px', transform: 'translate3d(0, 62px, 0)' })
    assert.equal('top' in style || 'left' in style, false)
    assert.deepEqual(hoverHighlightStyle(null), {})
  })
})

// ---------------------------------------------------------------------------
// Harness
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

async function startKovo(dataDir: string): Promise<KovoServer> {
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(process.execPath, [...HARDENED_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), KOVO_DATA_DIR: dataDir, KOVO_OFFLINE: '', KOVO_PUBLIC_ORIGIN: '' },
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

// ---------------------------------------------------------------------------
// Seed: three namesake projects, one unique project, 12 runs (2 live)
// ---------------------------------------------------------------------------

const DUP_NAME = 'Shopflow storefront regression'

interface Seed {
  dupIds: string[]
  uniqueId: string
  runId: string
  liveRunIds: string[]
  totalRuns: number
}

async function seedWorkspace(dataDir: string): Promise<Seed> {
  const { Store } = await import('../src/server/store.ts')
  const s = new Store(dataDir)
  const mk = (name: string, seeds: string[]) =>
    s.createProject({ requestId: randomUUID(), name, seeds, environment: 'public', includeSubdomains: false } as never)
  const mkRun = (projectId: string, goal: string) =>
    s.createRun({
      requestId: randomUUID(), projectId, goal, sourceMode: 'public', capabilityTier: 1, budgetUsd: 25,
      budgetRequests: 0, maxRpsPerOrigin: 5, workerConcurrency: 1, workerMaxTurns: 4,
    } as never)
  try {
    const dupA = mk(DUP_NAME, ['https://shop-a.example.com'])
    const dupB = mk(DUP_NAME, ['https://shop-b.example.com'])
    const dupC = mk(DUP_NAME, ['https://shop-a.example.com'])
    const unique = mk('Northwind Commerce', ['https://northwind.example.com'])
    const plan: [string, string, string][] = [
      // Live pair uses the legacy live alias `queued`: crash recovery and the
      // (model-less) executor only touch `running`, so the fixture stays stable.
      // `running` itself is covered by the buildRailFeed unit test.
      [unique.id, 'Authenticated checkout sweep', 'queued'],
      [dupB.id, 'Tenant isolation regression', 'queued'],
      [dupA.id, 'Baseline surface map', 'complete'],
      [dupA.id, 'Session fixation re-check', 'complete'],
      [dupB.id, 'Password reset flow review', 'failed'],
      [dupC.id, 'Cart pricing invariants', 'complete'],
      [unique.id, 'Search parameter review', 'paused'],
      [unique.id, 'Order export permissions', 'complete'],
      [dupC.id, 'Coupon stacking checks', 'stopped'],
      [dupA.id, 'Upload handling review', 'complete'],
      [unique.id, 'Admin route inventory', 'complete'],
      [dupB.id, 'Rate limit verification', 'complete'],
    ]
    const now = Date.now()
    const setRun = s.client.prepare('UPDATE runs SET status = ?, phase = ?, created_at = ? WHERE id = ?')
    const ids = plan.map(([projectId, goal, status], i) => {
      const r = mkRun(projectId, goal)
      setRun.run(status, status === 'complete' ? 'complete' : 'investigation', now - (i + 1) * 7 * 60_000, r.id)
      return r.id
    })
    return {
      dupIds: [dupA.id, dupB.id, dupC.id],
      uniqueId: unique.id,
      runId: ids[7]!,
      liveRunIds: ids.slice(0, 2),
      totalRuns: plan.length,
    }
  } finally {
    s.close()
  }
}

// ---------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------

type Theme = 'light' | 'dark'
interface Viewport { width: number; height: number; label: string }
const VIEWPORTS: readonly Viewport[] = [
  { width: 1280, height: 720, label: '1280x720' },
  { width: 1440, height: 900, label: '1440x900' },
]
const THEMES: readonly Theme[] = ['light', 'dark']
const SHOT_DIR = process.env.KOVO_UI_W2A_SCREENSHOT_DIR?.trim() || ''

async function shot(page: Page, name: string, vp: Viewport, theme: Theme): Promise<void> {
  if (!SHOT_DIR) return
  mkdirSync(SHOT_DIR, { recursive: true })
  await delay(220)
  await page.screenshot({ path: join(SHOT_DIR, `${name}--${vp.label}--${theme}.png`) })
}

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.evaluate(() => document.fonts?.ready).catch(() => {})
}

async function horizontalOverflow(page: Page, selector: string): Promise<string[]> {
  return page.$$eval(selector, els => els
    .filter(el => el.getClientRects().length > 0 && el.scrollWidth > el.clientWidth + 1)
    .map(el => `${el.tagName.toLowerCase()}[${el.getAttribute('data-slot') ?? el.className.toString().slice(0, 40)}] ${el.scrollWidth}>${el.clientWidth}`))
}

async function verticalClipping(page: Page, selector: string): Promise<string[]> {
  return page.$$eval(selector, els => els
    .filter(el => el.getClientRects().length > 0 && el.scrollHeight > el.clientHeight + 2)
    .map(el => `${el.tagName.toLowerCase()} "${(el.textContent ?? '').trim().slice(0, 30)}" ${el.scrollHeight}>${el.clientHeight}`))
}

/** Pairs of visible sibling controls inside `container` whose boxes overlap. */
async function overlappingSiblings(page: Page, container: string): Promise<string[]> {
  return page.$$eval(container, roots => roots.flatMap(root => {
    const kids = [...root.children]
      .filter(el => el.getClientRects().length > 0 && el.getAttribute('data-slot') !== 'hover-highlight')
      .map(el => ({ el, r: el.getBoundingClientRect() }))
    const out: string[] = []
    for (let i = 0; i < kids.length; i += 1) {
      for (let j = i + 1; j < kids.length; j += 1) {
        const a = kids[i]!.r
        const b = kids[j]!.r
        if (a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5) {
          out.push(`${kids[i]!.el.tagName}/${kids[j]!.el.tagName} in ${root.getAttribute('data-slot') ?? root.tagName}`)
        }
      }
    }
    return out
  }))
}

async function openPalette(page: Page): Promise<Locator> {
  await page.locator('body').click({ position: { x: 900, y: 690 } }).catch(() => {})
  await page.keyboard.press('Control+k')
  const popup = page.locator('[data-slot=dialog-content][aria-label="Command palette"]')
  await popup.waitFor({ state: 'visible' })
  return popup
}

async function activeDescendant(page: Page): Promise<{ id: string; activeId: string }> {
  return page.evaluate(() => ({
    id: document.querySelector('input[aria-label="Search workspace"]')?.getAttribute('aria-activedescendant') ?? '',
    activeId: document.querySelector('#gp-list [data-active="true"]')?.id ?? '',
  }))
}

/** Time (ms) from now until `locator` is visible, or Infinity after `limit`. */
async function msUntilVisible(locator: Locator, limit = 2_000): Promise<number> {
  const started = Date.now()
  try {
    await locator.waitFor({ state: 'visible', timeout: limit })
    return Date.now() - started
  } catch {
    return Number.POSITIVE_INFINITY
  }
}

function tooltip(page: Page, text: string): Locator {
  return page.locator('[data-slot=tooltip-content]', { hasText: text })
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('Wave 2A palette / rail / micro-interactions (Playwright)', { timeout: 600_000 }, () => {
  let skipReason: string | null = null
  let browser: Browser | undefined
  let kovo: KovoServer | undefined
  let seed: Seed | undefined
  const pageErrors: string[] = []

  before(async () => {
    const pwEnv = await loadPlaywright()
    if (!pwEnv) { skipReason = 'Playwright/Chromium unavailable'; return }
    if (!existsSync(resolve('build/server/server.js'))) execFileSync('npm', ['run', 'build'], { stdio: 'pipe' })
    const dataDir = await mkdtemp(join(tmpdir(), 'kovo-ui-w2a-'))
    seed = await seedWorkspace(dataDir)
    ;[kovo, browser] = await Promise.all([
      startKovo(dataDir),
      pwEnv.pw.chromium.launch({ headless: true, executablePath: pwEnv.executablePath, args: ['--no-sandbox'] }),
    ])
  })

  after(async () => {
    await browser?.close().catch(() => {})
    await kovo?.stop().catch(() => {})
  })

  async function withPage<T>(
    vp: Viewport,
    theme: Theme,
    fn: (page: Page) => Promise<T>,
    extra: Parameters<Browser['newContext']>[0] = {},
  ): Promise<T> {
    const ctx: BrowserContext = await browser!.newContext({ viewport: { width: vp.width, height: vp.height }, colorScheme: theme, ...extra })
    const url = new URL(kovo!.origin)
    await ctx.addCookies(kovo!.cookies.map(c => ({ ...c, domain: url.hostname, path: '/' })))
    await ctx.addInitScript(t => { try { localStorage.setItem('kovo-appearance', t) } catch { /* ignore */ } }, theme)
    const page = await ctx.newPage()
    page.on('pageerror', err => pageErrors.push(`${vp.label}/${theme}: ${err.message}`))
    try {
      return await fn(page)
    } catch (err) {
      if (SHOT_DIR) await page.screenshot({ path: join(SHOT_DIR, `FAIL--${vp.label}--${theme}--${Date.now()}.png`) }).catch(() => {})
      throw err
    } finally {
      await ctx.close()
    }
  }

  async function home(page: Page): Promise<void> {
    await page.goto(kovo!.origin + '/', { waitUntil: 'domcontentloaded' })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor()
    await settle(page)
  }

  const desktop = VIEWPORTS[0]!

  it('[U19] palette: combobox ARIA, grouped listbox, activedescendant tracks ↑/↓, polite count', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'light', async page => {
      await home(page)
      const popup = await openPalette(page)
      const combo = popup.getByRole('combobox', { name: 'Command palette search' })
      assert.equal(await combo.getAttribute('aria-expanded'), 'true')
      assert.equal(await combo.getAttribute('aria-controls'), 'gp-list')
      const input = popup.getByRole('textbox', { name: 'Search workspace' })
      assert.equal(await input.getAttribute('aria-controls'), 'gp-list')
      assert.equal(await input.getAttribute('aria-autocomplete'), 'list')
      assert.ok(await input.evaluate(el => el === document.activeElement), 'input keeps focus')

      const list = popup.locator('#gp-list')
      assert.equal(await list.getAttribute('role'), 'listbox')
      assert.equal(await list.getAttribute('aria-label'), 'Command palette results')
      for (const name of ['Navigation', 'Projects', 'Recent runs', 'Actions']) {
        assert.equal(await list.getByRole('group', { name, exact: true }).count(), 1, `group ${name}`)
      }
      const groups = await list.evaluate(el => [...el.querySelectorAll('[role=group]')].map(g => {
        const head = document.getElementById(g.getAttribute('aria-labelledby') ?? '')
        return { head: head?.textContent?.trim() ?? '', options: g.querySelectorAll('[role=option]').length, inside: Boolean(head && g.contains(head)) }
      }))
      assert.ok(groups.every(g => g.head && g.inside && g.options > 0), JSON.stringify(groups))

      let ad = await activeDescendant(page)
      assert.equal(ad.id, 'gp-opt-nav.projects')
      assert.equal(ad.id, ad.activeId)
      await page.keyboard.press('ArrowDown')
      ad = await activeDescendant(page)
      assert.equal(ad.id, 'gp-opt-nav.settings')
      assert.equal(ad.id, ad.activeId)
      assert.equal(await popup.locator(`[id="${ad.id}"]`).getAttribute('aria-selected'), 'true')
      await page.keyboard.press('ArrowDown')
      await page.keyboard.press('ArrowUp')
      assert.equal((await activeDescendant(page)).id, 'gp-opt-nav.settings')
      // The highlight is instant: no eased trail behind ↑/↓.
      assert.equal(await popup.locator('[data-active="true"]').evaluate(el => getComputedStyle(el).transitionDuration), '0s')

      const status = popup.locator('[role=status][aria-live=polite]')
      assert.match(await status.innerText(), /^\d+ results$/)
      await input.fill('northwind')
      await page.waitForFunction(() => /^\d+ results?$/.test(document.querySelector('[data-slot=palette-announcement]')?.textContent ?? ''))
      const filtered = await activeDescendant(page)
      assert.equal(filtered.id, filtered.activeId, 'activedescendant resets to the first match on query change')
      assert.ok(filtered.id.startsWith('gp-opt-'), filtered.id)
    })
  })

  it('[U19] palette: zero matches render actionable fallbacks (clear, settings, create project)', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'dark', async page => {
      await home(page)
      let popup = await openPalette(page)
      const input = popup.getByRole('textbox', { name: 'Search workspace' })
      await input.fill('zzqx-nothing')
      await popup.getByText(/No matches for/).waitFor({ state: 'visible' })
      const suggestions = popup.getByRole('group', { name: 'Suggestions' })
      assert.deepEqual(
        (await suggestions.getByRole('option').allInnerTexts()).map(s => s.trim()),
        ['Create project “zzqx-nothing”', 'Search settings', 'Clear search'],
      )
      assert.equal(await popup.locator('[role=status]').innerText(), 'No exact matches, 3 fallback actions')
      assert.equal((await activeDescendant(page)).id, 'gp-opt-fb.create-project')
      await shot(page, 'palette-no-match-fallbacks', desktop, 'dark')

      // Clear search keeps the palette open and refocuses the field.
      await page.keyboard.press('ArrowDown')
      await page.keyboard.press('ArrowDown')
      assert.equal((await activeDescendant(page)).id, 'gp-opt-fb.clear')
      await page.keyboard.press('Enter')
      assert.equal(await input.inputValue(), '')
      assert.ok(await popup.isVisible(), 'palette stays open')
      assert.ok(await input.evaluate(el => el === document.activeElement), 'field refocused')
      assert.equal((await activeDescendant(page)).id, 'gp-opt-nav.projects')

      // Search settings navigates.
      await input.fill('zzqx-nothing')
      await page.keyboard.press('ArrowDown')
      await page.keyboard.press('Enter')
      await page.waitForURL(/\/settings/)
      await popup.waitFor({ state: 'detached' })

      // Create project opens the New project sheet (pointer path).
      await home(page)
      popup = await openPalette(page)
      await popup.getByRole('textbox', { name: 'Search workspace' }).fill('zzqx-nothing')
      await popup.getByRole('option', { name: /Create project/ }).click()
      await page.locator('[data-slot=dialog-content][aria-label="New project"]').waitFor({ state: 'visible' })
    })
  })

  it('[U20] warm-up tooltips: first waits, siblings open instantly, hide at once on leave, keyboard focus opens', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'light', async page => {
      await home(page)
      const helpBtn = page.locator('aside').getByRole('button', { name: 'Keyboard shortcuts' })
      const themeBtn = page.locator('aside').getByRole('button', { name: /^(Light|Dark)$/ })
      assert.equal(await helpBtn.getAttribute('title'), null, 'native title removed from tooltipped trigger')
      assert.equal(await themeBtn.getAttribute('title'), null)

      await page.mouse.move(700, 400)
      await helpBtn.hover()
      await delay(250)
      assert.equal(await tooltip(page, 'Keyboard shortcuts').count(), 0, 'first tooltip still waiting at 250ms')
      const first = await msUntilVisible(tooltip(page, 'Keyboard shortcuts'))
      assert.ok(first < 900, `first tooltip opened after the delay (${first + 250}ms)`)
      assert.equal(await tooltip(page, 'Keyboard shortcuts').getAttribute('data-instant'), null, 'first open animates')
      assert.match(await tooltip(page, 'Keyboard shortcuts').evaluate(el => getComputedStyle(el).transitionProperty), /scale/)

      await themeBtn.hover()
      const warm = await msUntilVisible(tooltip(page, 'Toggle theme'), 400)
      assert.ok(warm < 200, `warm sibling opens immediately (${warm}ms)`)
      assert.notEqual(await tooltip(page, 'Toggle theme').getAttribute('data-instant'), null, 'warm sibling skips the transition')
      assert.equal(await tooltip(page, 'Toggle theme').evaluate(el => getComputedStyle(el).transitionDuration), '0s')
      await tooltip(page, 'Keyboard shortcuts').waitFor({ state: 'detached', timeout: 300 })
      await shot(page, 'shell-tooltip-warm', desktop, 'light')

      const left = Date.now()
      await page.mouse.move(800, 300)
      await tooltip(page, 'Toggle theme').waitFor({ state: 'detached', timeout: 400 })
      assert.ok(Date.now() - left < 300, 'tooltip hides at once on leave')

      // Keyboard focus opens without the hover delay.
      await page.mouse.move(800, 300)
      await delay(TOOLTIP_WARM_TIMEOUT_MS + 200)
      await page.keyboard.press('Shift')
      await helpBtn.focus()
      const focused = await msUntilVisible(tooltip(page, 'Keyboard shortcuts'), 400)
      assert.ok(focused < 250, `focus opens immediately (${focused}ms)`)
    })
  })

  it('[U20] tooltips respect prefers-reduced-motion (opacity only, no scale travel)', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'dark', async page => {
      await home(page)
      await page.locator('aside').getByRole('button', { name: 'Keyboard shortcuts' }).hover()
      const tip = tooltip(page, 'Keyboard shortcuts')
      await tip.waitFor({ state: 'visible' })
      const motion = await tip.evaluate(el => ({ property: getComputedStyle(el).transitionProperty, scale: getComputedStyle(el).scale }))
      assert.doesNotMatch(motion.property, /scale|transform/)
      assert.equal(motion.scale, 'none')
    }, { reducedMotion: 'reduce' })
  })

  it('[U20] mouse-only nav hover highlight: glides between rows, clears on leave, keyboard and touch', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'light', async page => {
      await home(page)
      const nav = page.getByRole('navigation', { name: 'Workspace' })
      const hl = nav.locator('[data-slot=hover-highlight]')
      const read = () => hl.evaluate(el => ({
        visible: el.hasAttribute('data-visible'),
        glide: el.hasAttribute('data-glide'),
        y: new DOMMatrixReadOnly(getComputedStyle(el).transform).m42,
        height: el.getBoundingClientRect().height,
        transition: getComputedStyle(el).transitionProperty,
        usesLayoutProps: Boolean(el.style.top || el.style.left),
      }))
      const projects = nav.getByRole('link', { name: 'Projects' })
      const settings = nav.getByRole('link', { name: 'Settings' })
      await page.mouse.move(700, 400)
      await projects.hover()
      let s = await read()
      assert.ok(s.visible && !s.glide, 'appears in place on first hover')
      assert.equal(Math.round(s.height), 30)
      const projectsTop = await projects.evaluate((el, navEl) => el.getBoundingClientRect().top - navEl!.getBoundingClientRect().top, await nav.elementHandle())
      assert.ok(Math.abs(s.y - projectsTop) <= 1, `highlight y ${s.y} vs ${projectsTop}`)
      await settings.hover()
      await delay(200)
      s = await read()
      const settingsTop = await settings.evaluate((el, navEl) => el.getBoundingClientRect().top - navEl!.getBoundingClientRect().top, await nav.elementHandle())
      assert.ok(s.visible && s.glide, 'glides between rows')
      assert.ok(Math.abs(s.y - settingsTop) <= 1, `glided to ${s.y} (expected ${settingsTop})`)
      assert.match(s.transition, /transform/)
      assert.equal(s.usesLayoutProps, false, 'never animates top/left')
      await shot(page, 'shell-nav-hover-highlight', desktop, 'light')

      await page.mouse.move(700, 400)
      assert.equal((await read()).visible, false, 'pointer leave clears it')
      await projects.hover()
      assert.equal((await read()).visible, true)
      await page.keyboard.press('Shift')
      assert.equal((await read()).visible, false, 'any key press clears hover (no sticky highlight for keyboard users)')

      // Emulated mouse right after a touch never lights it.
      await page.mouse.move(700, 400)
      const emulated = await nav.evaluate(navEl => {
        const link = navEl.querySelector('a[data-hover-item]')!
        link.dispatchEvent(new PointerEvent('pointerdown', { pointerType: 'touch', bubbles: true }))
        link.dispatchEvent(new PointerEvent('pointerup', { pointerType: 'touch', bubbles: true }))
        link.dispatchEvent(new PointerEvent('pointermove', { pointerType: 'mouse', bubbles: true }))
        link.dispatchEvent(new PointerEvent('pointermove', { pointerType: 'touch', bubbles: true }))
        return navEl.querySelector('[data-slot=hover-highlight]')!.hasAttribute('data-visible')
      })
      assert.equal(emulated, false, 'post-tap emulated mouse and touch moves are ignored')
    })

    // Coarse-pointer devices never render the highlight at all.
    await withPage(desktop, 'dark', async page => {
      await home(page)
      const display = await page.locator('nav[aria-label=Workspace] [data-slot=hover-highlight]').evaluate(el => getComputedStyle(el).display)
      assert.equal(display, 'none')
    }, { hasTouch: true, isMobile: true })

    // Reduced motion: the glide snaps (no transform in the transition list).
    await withPage(desktop, 'light', async page => {
      await home(page)
      const nav = page.getByRole('navigation', { name: 'Workspace' })
      await nav.getByRole('link', { name: 'Projects' }).hover()
      await nav.getByRole('link', { name: 'Settings' }).hover()
      assert.doesNotMatch(await nav.locator('[data-slot=hover-highlight]').evaluate(el => getComputedStyle(el).transitionProperty), /transform/)
    }, { reducedMotion: 'reduce' })
  })

  it('[U20] run workspace rail: own warm-up group, view tooltips with shortcuts, hover highlight', async t => {
    if (skipReason) return t.skip(skipReason)
    for (const vp of VIEWPORTS) {
      for (const theme of THEMES) {
        await withPage(vp, theme, async page => {
          await page.goto(`${kovo!.origin}/runs/${seed!.runId}`, { waitUntil: 'domcontentloaded' })
          const rail = page.locator('aside[aria-label="Run navigation"]')
          await rail.waitFor({ state: 'visible', timeout: 20_000 })
          await settle(page)
          const views = rail.getByRole('navigation', { name: 'Investigation views' })
          const buttons = views.getByRole('button')
          assert.ok(await buttons.count() >= 3)
          assert.equal(await buttons.first().getAttribute('title'), null, 'view buttons drop native titles')
          await page.mouse.move(vp.width - 200, vp.height - 200)
          await buttons.nth(1).hover()
          const label = (await buttons.nth(1).innerText()).split('\n')[0]!.trim()
          const tip = page.locator('[data-slot=tooltip-content]')
          await tip.waitFor({ state: 'visible', timeout: 2_000 })
          assert.match(await tip.innerText(), new RegExp(`^${label}\\s*G then [A-Z]$`))
          assert.ok(await views.locator('[data-slot=hover-highlight]').evaluate(el => el.hasAttribute('data-visible')))
          await buttons.nth(2).hover()
          await delay(60)
          assert.equal(await page.locator('[data-slot=tooltip-content][data-instant]').count(), 1, 'warm sibling instant inside the run rail')
          assert.deepEqual(await horizontalOverflow(page, 'aside[aria-label="Run navigation"], aside nav'), [])
          assert.deepEqual(await verticalClipping(page, 'aside[aria-label="Run navigation"] nav button'), [])
          await shot(page, 'run-rail-tooltip-hover', vp, theme)
          await page.mouse.move(vp.width - 200, vp.height - 200)
          await tip.waitFor({ state: 'detached', timeout: 400 })
          assert.equal(await views.locator('[data-slot=hover-highlight]').evaluate(el => el.hasAttribute('data-visible')), false)
        })
      }
    }
  })

  it('[U14] projects index: namesake disambiguation, persistent quiet row actions, no overlap', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'light', async page => {
      await home(page)
      const dupRows = page.locator('[data-slot=project-row]', { hasText: DUP_NAME })
      assert.equal(await dupRows.count(), 3)
      const suffixes = await dupRows.locator('[data-slot=project-name-disambiguator]').allInnerTexts()
      assert.equal(suffixes.length, 3)
      assert.equal(new Set(suffixes).size, 3, `distinct suffixes ${suffixes.join(' | ')}`)
      assert.ok(suffixes.includes('shop-b.example.com'), suffixes.join(' | '))
      assert.ok(suffixes.filter(sfx => /^#[0-9a-f]{6}$/.test(sfx)).length === 2, suffixes.join(' | '))
      const clipped = await dupRows.locator('[data-slot=project-name-disambiguator]').evaluateAll(els => els.filter(el => el.scrollWidth > el.clientWidth + 1).length)
      assert.equal(clipped, 0, 'distinguishing suffix never clipped')
      const unique = page.locator('[data-slot=project-row]', { hasText: 'Northwind Commerce' })
      assert.equal(await unique.locator('[data-slot=project-name-disambiguator]').count(), 0)

      await page.mouse.move(5, 5)
      const actions = unique.locator('[data-slot=project-row-actions]')
      assert.ok(await actions.isVisible(), 'actions present without hover')
      const quiet = Number(await actions.evaluate(el => getComputedStyle(el).opacity))
      assert.ok(quiet > 0.3 && quiet < 0.6, `quiet opacity ${quiet}`)
      const newRun = unique.getByRole('link', { name: /^New run for/ })
      const more = unique.getByRole('button', { name: /^More actions for/ })
      assert.ok(await newRun.isVisible() && await more.isVisible())
      assert.equal(await newRun.getAttribute('title'), null)
      const geo = await unique.evaluate(row => {
        const a = row.querySelector('[data-slot=project-row-actions]')!.getBoundingClientRect()
        const m = row.querySelector('[data-slot=project-row-metrics]')!.getBoundingClientRect()
        const r = row.getBoundingClientRect()
        return { overlap: a.left < m.right && m.left < a.right, width: a.width, inside: a.right <= r.right && a.left >= r.left }
      })
      assert.equal(geo.overlap, false, 'actions never overlay the metrics')
      assert.ok(Math.abs(geo.width - 72) <= 1, `72px action column (${geo.width})`)
      assert.ok(geo.inside)
      const metricsBefore = await unique.locator('[data-slot=project-row-metrics]').boundingBox()
      await unique.hover()
      await delay(200)
      assert.equal(Number(await actions.evaluate(el => getComputedStyle(el).opacity)), 1, 'full opacity on row hover')
      assert.deepEqual(await unique.locator('[data-slot=project-row-metrics]').boundingBox(), metricsBefore, 'no layout shift on hover')
      assert.equal(Number(await unique.locator('[data-slot=project-row-metrics]').evaluate(el => getComputedStyle(el).opacity)), 1, 'metrics stay visible on hover')
      await newRun.hover()
      await tooltip(page, 'New run').waitFor({ state: 'visible' })
      await shot(page, 'projects-row-actions-tooltip', desktop, 'light')

      await more.click()
      const menu = page.getByRole('menu')
      await menu.waitFor({ state: 'visible' })
      await menu.getByRole('menuitem', { name: 'All runs' }).click()
      await page.waitForURL(new RegExp(`/projects/${seed!.uniqueId}\\?tab=runs`))
    })
  })

  it('[U14] projects index keyboard rows: j/k/↑/↓ instant highlight, Enter opens, R new run, no hijack while typing', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'dark', async page => {
      await home(page)
      const rows = page.locator('[data-slot=project-row]')
      const activeIndex = () => page.evaluate(() => [...document.querySelectorAll('[data-slot=project-row]')].findIndex(r => r.hasAttribute('data-active')))
      await page.locator('main h1').click()
      assert.equal(await activeIndex(), -1)
      await page.keyboard.press('ArrowDown')
      assert.equal(await activeIndex(), -1, 'arrows do not engage row navigation on their own')
      await page.keyboard.press('j')
      assert.equal(await activeIndex(), 0)
      assert.equal(await rows.nth(0).evaluate(el => getComputedStyle(el).transitionDuration), '0s', 'instant highlight')
      assert.ok(await rows.nth(0).locator('[data-slot=project-name-link]').evaluate(el => el === document.activeElement), 'active row link takes focus')
      await page.keyboard.press('j')
      await page.keyboard.press('ArrowDown')
      assert.equal(await activeIndex(), 2)
      await page.keyboard.press('k')
      assert.equal(await activeIndex(), 1)
      await page.keyboard.press('ArrowUp')
      assert.equal(await activeIndex(), 0)
      const bg = await rows.nth(0).evaluate(el => getComputedStyle(el).boxShadow)
      assert.match(bg, /inset/, 'visible active indicator')
      await delay(200)
      assert.equal(Number(await rows.nth(0).locator('[data-slot=project-row-actions]').evaluate(el => getComputedStyle(el).opacity)), 1)
      await page.keyboard.press('j')
      await shot(page, 'projects-keyboard-row-active', desktop, 'dark')
      const secondHref = await rows.nth(1).locator('[data-slot=project-name-link]').getAttribute('href')
      await page.keyboard.press('Enter')
      await page.waitForURL(url => url.pathname === secondHref)

      await home(page)
      await page.locator('main h1').click()
      await page.keyboard.press('j')
      await page.keyboard.press('r')
      await page.waitForURL(/\/projects\/[0-9a-f-]+\?newRun=/)

      // Typing in the filter never moves rows.
      await home(page)
      const filter = page.getByRole('searchbox', { name: 'Filter projects' })
      await filter.click()
      await page.keyboard.type('jk')
      assert.equal(await filter.inputValue(), 'jk')
      assert.equal(await activeIndex(), -1)
      await filter.fill('')
      // Global shortcuts still win: `n` opens New project, and j/k are inert under the open sheet.
      await page.locator('main h1').click()
      await page.keyboard.press('n')
      await page.locator('[data-slot=dialog-content][aria-label="New project"]').waitFor({ state: 'visible' })
      await page.keyboard.press('Escape')
      await page.locator('[data-slot=dialog-content][aria-label="New project"]').waitFor({ state: 'detached' })
      await page.keyboard.press('Control+k')
      await page.locator('[data-slot=dialog-content][aria-label="Command palette"]').waitFor({ state: 'visible' })
      await page.keyboard.press('j')
      assert.equal(await activeIndex(), -1, 'no row movement while the palette is open')
    })
  })

  it('[U14] grouped rail feed: live runs pinned, each project named once, capped with View all runs', async t => {
    if (skipReason) return t.skip(skipReason)
    await withPage(desktop, 'light', async page => {
      await home(page)
      const feed = page.locator('aside [data-slot=rail-feed]')
      await feed.waitFor()
      const live = feed.locator('[data-slot=rail-feed-live]')
      assert.equal(await live.count(), 2)
      for (const id of seed!.liveRunIds) {
        assert.equal(await feed.locator(`[data-slot=rail-feed-live][href="/runs/${id}"]`).count(), 1, `live run ${id} pinned`)
      }
      const elapsed = await live.locator('[data-slot=rail-feed-elapsed]').evaluateAll(els => els.map(el => ({ text: el.textContent ?? '', num: getComputedStyle(el).fontVariantNumeric })))
      assert.ok(elapsed.every(e => /^(now|\d+m|\d+h \d\dm)$/.test(e.text) && e.num.includes('tabular-nums')), JSON.stringify(elapsed))
      const order = await feed.evaluate(el => [...el.querySelectorAll('[data-slot=rail-feed-live], [data-slot=rail-feed-group-header]')].map(n => n.getAttribute('data-slot')))
      assert.equal(order.slice(0, 2).join(), 'rail-feed-live,rail-feed-live', 'live runs pinned above the groups')
      const headers = await feed.locator('[data-slot=rail-feed-group-header]').evaluateAll(els => els.map(el => el.getAttribute('href')))
      assert.equal(new Set(headers).size, headers.length, 'each project named once')
      const runRows = await feed.locator('[data-slot=rail-feed-run]').count()
      assert.equal(runRows + 2, 8, 'feed capped at 8 rows')
      const indent = await feed.locator('[data-slot=rail-feed-run]').first().evaluate(el => parseFloat(getComputedStyle(el).paddingLeft))
      assert.ok(indent >= 18, `run rows indented under their project (${indent}px)`)
      const viewAll = feed.locator('[data-slot=rail-feed-view-all]')
      assert.match(await viewAll.innerText(), new RegExp(`View all runs\\s*\\+${seed!.totalRuns - 8}`))
      const dupHeaders = await feed.locator('[data-slot=rail-feed-group-header]', { hasText: DUP_NAME }).count()
      assert.ok(dupHeaders >= 2, 'feed shows namesake projects')
      assert.equal(await feed.locator('[data-slot=rail-feed-group-header]', { hasText: DUP_NAME }).locator('[data-slot=rail-feed-disambiguator]').count(), dupHeaders)
      assert.equal(await feed.locator('[data-slot=rail-feed-group-header]', { hasText: 'Northwind' }).locator('[data-slot=rail-feed-disambiguator]').count(), 0)
      const text = await page.locator('aside').innerText()
      assert.doesNotMatch(text, /undefined|null|NaN/)
    })
    for (const vp of VIEWPORTS) {
      for (const theme of THEMES) {
        await withPage(vp, theme, async page => {
          await home(page)
          await page.locator('aside [data-slot=rail-feed-live]').first().waitFor()
          assert.deepEqual(await horizontalOverflow(page, 'aside, [data-slot=rail-feed], [data-slot=rail-feed] a'), [], `${vp.label}/${theme}: feed overflow`)
          await page.locator('aside [data-slot=rail-feed-run]').nth(1).hover()
          await shot(page, 'rail-feed-live-grouped', vp, theme)
        })
      }
    }
  })

  it(':where(a) reset: Tailwind text-* utilities on <Link> resolve to the utility colour', async t => {
    if (skipReason) return t.skip(skipReason)
    for (const theme of THEMES) {
      await withPage(desktop, theme, async page => {
        await home(page)
        const res = await page.evaluate(() => {
          const probe = document.createElement('span')
          probe.className = 'text-fg-subtle'
          document.querySelector('aside')!.appendChild(probe)
          const expected = getComputedStyle(probe).color
          probe.remove()
          const link = document.querySelector<HTMLAnchorElement>('[data-slot=rail-feed-group-header]')!
          const parentColor = getComputedStyle(link.parentElement!).color
          const injected = document.createElement('a')
          injected.href = '#'
          injected.className = 'text-accent underline'
          document.querySelector('main')!.appendChild(injected)
          const accentProbe = document.createElement('span')
          accentProbe.className = 'text-accent'
          document.querySelector('main')!.appendChild(accentProbe)
          const out = {
            expected,
            link: getComputedStyle(link).color,
            parentColor,
            injected: getComputedStyle(injected).color,
            accent: getComputedStyle(accentProbe).color,
            underline: getComputedStyle(injected).textDecorationLine,
            bare: (() => { const a = document.createElement('a'); a.href = '#'; document.body.appendChild(a); const c = getComputedStyle(a).textDecorationLine; a.remove(); return c })(),
          }
          injected.remove()
          accentProbe.remove()
          return out
        })
        assert.equal(res.link, res.expected, `${theme}: Link text-fg-subtle resolves to the utility colour`)
        assert.notEqual(res.link, res.parentColor, `${theme}: not inherited from the parent`)
        assert.equal(res.injected, res.accent, `${theme}: text-accent on <a>`)
        assert.equal(res.underline, 'underline', 'underline utility wins over the reset')
        assert.equal(res.bare, 'none', 'bare links stay undecorated')
      })
    }
  })

  it('geometry + screenshots at 1280×720 and 1440×900 (light & dark): no overflow, CTA above the fold, no clipping/overlap', async t => {
    if (skipReason) return t.skip(skipReason)
    await Promise.all(VIEWPORTS.flatMap(vp => THEMES.map(theme => withPage(vp, theme, async page => {
      const ctx = `${vp.label}/${theme}`
      await home(page)
      assert.deepEqual(await horizontalOverflow(page, 'main, main > div, [data-slot=project-row], aside, aside nav, [data-slot=rail-feed]'), [], `${ctx}: horizontal overflow`)
      const docOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      assert.ok(docOverflow <= 0, `${ctx}: document overflow ${docOverflow}`)
      const cta = await page.locator('header').getByRole('button', { name: 'New project' }).boundingBox()
      assert.ok(cta && cta.x >= 0 && cta.x + cta.width <= vp.width && cta.y >= 0 && cta.y + cta.height <= vp.height, `${ctx}: New project CTA above the fold`)
      assert.deepEqual(await verticalClipping(page, '[data-slot=project-row-actions] a, [data-slot=project-row-actions] button, aside a, aside button, [data-slot=project-row-metrics]'), [], `${ctx}: clipped text`)
      assert.deepEqual(await overlappingSiblings(page, '[data-slot=project-row-actions], [data-slot=project-row], aside nav, [data-slot=rail-feed-group]'), [], `${ctx}: overlapping siblings`)
      await page.locator('main h1').click()
      await page.keyboard.press('j')
      await page.keyboard.press('j')
      await page.locator('aside nav[aria-label=Workspace]').getByRole('link', { name: 'Projects' }).hover()
      await shot(page, 'projects-index-dupes-keyboard-rail', vp, theme)

      const popup = await openPalette(page)
      await popup.getByRole('textbox', { name: 'Search workspace' }).fill('zzqx-nothing')
      await popup.getByRole('group', { name: 'Suggestions' }).waitFor()
      assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content], #gp-list, [role=option]'), [], `${ctx}: palette overflow`)
      assert.deepEqual(await verticalClipping(page, '[role=option]'), [], `${ctx}: palette options clipped`)
      const box = await popup.boundingBox()
      assert.ok(box && box.y + box.height <= vp.height, `${ctx}: palette in viewport`)
      await shot(page, 'palette-no-match-fallbacks', vp, theme)
      await popup.getByRole('textbox', { name: 'Search workspace' }).fill('')
      await page.keyboard.press('ArrowDown')
      await shot(page, 'palette-grouped-listbox', vp, theme)
    }))))
  })

  it('no uncaught page errors', t => {
    if (skipReason) return t.skip(skipReason)
    assert.deepEqual(pageErrors, [])
  })
})
