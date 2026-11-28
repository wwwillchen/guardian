// The run workspace shell: providers, rail, run line header, view outlet,
// resizable inspector pane, global keyboard model, palette, toasts.
import { Link, useNavigate, useRouter } from '@tanstack/react-router'
import { Component, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { BoardPane, useBoardSeen } from './coordinator.tsx'
import { RunDataProvider, useRun } from './data.tsx'
import { ACTIONS, approvalCommand, DecisionsProvider, useDecisions } from './decisions.tsx'
import { fmtN, fmtUsd, host, RUN_SUBMODE_PARAMS } from './format.ts'
import { openBudgetPopover, RunHeader } from './header.tsx'
import { Icon } from './icons.tsx'
import { KeyboardProvider, useShortcuts } from './keyboard.tsx'
import { VIEWS } from './meta.ts'
import type { ViewId } from './meta.ts'
import type { Approval, Detail, RunEvent } from './model.ts'
import { NavProvider, selKey, useNav } from './nav.tsx'
import type { Sel } from './nav.tsx'
import { OverlaysProvider, useOverlays } from './overlays.tsx'
import { FallbackInspector, PaneLayoutProvider } from './pane.tsx'
import { PaletteProvider, usePalette } from './palette.tsx'
import { PanelErrorBoundary } from './panel-error-boundary.tsx'
import { Rail, RailFallback } from './rail.tsx'
import { useTheme } from './theme.ts'
import { ToastProvider, useToast } from './toast.tsx'
import { cn, runBtn } from './tw.ts'
import { ScopeOverlay } from './views/consent.tsx'
import { CHAT_FIRST_VIEWS, INSPECTORS, VIEW_COMPONENTS } from './views/index.tsx'

/** Landing view by run state: consent when waiting, the queue when decisions are pending, otherwise the overview. */
export function landingView(d: Detail): ViewId {
  if (d.run.status === 'waiting') return 'overview'
  if (d.approvals.some(a => a.status === 'pending')) return 'queue'
  return 'overview'
}

export function RunShell({ detail, view, sel }: { detail: Detail; view: ViewId; sel: Sel | null }) {
  const navigate = useNavigate()
  const runId = detail.run.id
  const curViewRef = useRef(view)
  curViewRef.current = view
  const go = useCallback((v: ViewId, s: Sel | null, push: boolean) => {
    const keepSubModes: [string, string][] = []
    if (v === curViewRef.current && typeof window !== 'undefined') {
      const sp = new URLSearchParams(window.location.search)
      for (const k of RUN_SUBMODE_PARAMS) {
        const val = sp.get(k)
        if (val) keepSubModes.push([k, val])
      }
    }
    void navigate({ to: '/runs/$runId', params: { runId }, search: { view: v, sel: s ? selKey(s) : undefined }, replace: !push, resetScroll: false }).then(() => {
      if (!keepSubModes.length || typeof window === 'undefined') return
      const url = new URL(window.location.href)
      let changed = false
      for (const [k, val] of keepSubModes) {
        if (url.searchParams.get(k) !== val) {
          url.searchParams.set(k, val)
          changed = true
        }
      }
      if (changed) window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
    })
  }, [navigate, runId])
  const switchRun = useCallback((id: string, v?: ViewId) => {
    void navigate({ to: '/runs/$runId', params: { runId: id }, search: v ? { view: v } : {} })
  }, [navigate])
  return <div className="relative h-screen overflow-clip bg-bg font-sans text-[13px] leading-5 tracking-[-0.003em] text-fg antialiased">
    <KeyboardProvider>
      <ToastProvider>
        <RunErrorBoundary resetKey={detail} projectId={detail.run.projectId} runId={runId}>
          <DataWithToasts detail={detail}>
            <NavWithRun runId={runId} view={view} sel={sel} go={go} switchRun={switchRun}>
              <DecisionsProvider>
                <OverlaysProvider>
                  <PaletteProvider>
                    <Workspace />
                  </PaletteProvider>
                </OverlaysProvider>
              </DecisionsProvider>
            </NavWithRun>
          </DataWithToasts>
        </RunErrorBoundary>
      </ToastProvider>
    </KeyboardProvider>
  </div>
}

interface RunErrorBoundaryProps {
  /** Changing this (e.g. a fresh `detail` after `router.invalidate()`) clears the error. */
  resetKey: unknown
  projectId: string
  runId: string
  children: ReactNode
}

/**
 * Run-level error boundary above `RunDataProvider`: a malformed record that
 * throws while building the run model keeps the rail and offers a reload,
 * instead of replacing the whole page with the root error screen.
 */
class RunErrorBoundary extends Component<RunErrorBoundaryProps, { error: string | null }> {
  override state: { error: string | null } = { error: null }

  static getDerivedStateFromError(error: unknown): { error: string } {
    const msg = error instanceof Error ? error.message.trim() : typeof error === 'string' ? error.trim() : ''
    return { error: msg.slice(0, 240) || 'Unexpected rendering error.' }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[kovo] run workspace failed to render', error, info.componentStack)
  }

  override componentDidUpdate(prev: RunErrorBoundaryProps): void {
    if (this.state.error !== null && prev.resetKey !== this.props.resetKey) this.setState({ error: null })
  }

  override render(): ReactNode {
    if (this.state.error === null) return this.props.children
    return <RunErrorFallback projectId={this.props.projectId} runId={this.props.runId} message={this.state.error} />
  }
}

function RunErrorFallback({ projectId, runId, message }: { projectId: string; runId: string; message: string }) {
  const router = useRouter()
  const [reloading, setReloading] = useState(false)
  const reload = () => {
    setReloading(true)
    void router.invalidate().finally(() => setReloading(false))
  }
  return <div className="grid h-screen grid-cols-[232px_minmax(0,1fr)] overflow-clip">
    <RailFallback projectId={projectId} runId={runId} />
    <main className="flex min-h-0 min-w-0 items-center justify-center overflow-clip bg-panel p-6" aria-label="Run">
      <div className="flex max-w-[440px] flex-col items-start gap-2.5" role="alert" data-testid="run-error-boundary">
        <span className="inline-flex size-8 items-center justify-center rounded-full bg-danger-soft text-danger"><Icon name="alert" /></span>
        <h2 className="m-0 text-[15px] font-semibold text-fg">This run couldn’t be displayed</h2>
        <p className="m-0 text-[12.5px] leading-[19px] text-fg-muted">
          A record in this run could not be read, so the workspace stopped rendering. Reloading fetches fresh run data; the scan itself is unaffected.
        </p>
        <p className="m-0 max-w-full break-words font-mono text-[11.5px] leading-[17px] text-fg-subtle [overflow-wrap:anywhere]">{message}</p>
        <div className="mt-1 flex items-center gap-1.5">
          <button type="button" className={runBtn({ variant: 'primary' })} disabled={reloading} onClick={reload} data-testid="run-error-reload">
            <Icon name="replay" />{reloading ? 'Reloading…' : 'Reload run'}
          </button>
          <Link className={runBtn({ variant: 'ghost' })} to="/projects/$projectId" params={{ projectId }} search={{ tab: 'runs' }}>Back to project</Link>
        </div>
      </div>
    </main>
  </div>
}

function DataWithToasts({ detail, children }: { detail: Detail; children: ReactNode }) {
  const toast = useToast()
  return <RunDataProvider initial={detail} onError={m => toast.show(m, { tone: 'error' })}>{children}</RunDataProvider>
}

function NavWithRun({ runId, view, sel, go, switchRun, children }: {
  runId: string
  view: ViewId
  sel: Sel | null
  go: (view: ViewId, sel: Sel | null, push: boolean) => void
  switchRun: (runId: string, view?: ViewId) => void
  children: ReactNode
}) {
  const { detail } = useRun()
  const hasPendingApprovals = detail.approvals.some(a => a.status === 'pending')
  return <NavProvider runId={runId} view={view} sel={sel} go={go} switchRun={switchRun} hasPendingApprovals={hasPendingApprovals}>{children}</NavProvider>
}

export const PANE_KEY = 'kovo-rw-pane'
export const PANE_PIN_KEY = 'kovo-rw-pane-pinned'
export const PANE_MIN = 320
export const PANE_DEFAULT = 404
export const PANE_MAX_CEILING = 760
/** Magnetic snap distance (px) around each snap width while dragging the resizer. */
export const PANE_SNAP_THRESHOLD = 4
/** Viewport range `[MIN, MAX]` where the inspector floats as an overlay unless pinned. */
export const PANE_OVERLAY_MIN_VP = 900
export const PANE_OVERLAY_MAX_VP = 1439

/** Widest inspector for a viewport: 58% of it, never above the 760px ceiling or below the minimum. */
export function maxPaneWidth(viewportWidth: number): number {
  if (!(viewportWidth > 0)) return 640
  return Math.max(PANE_MIN, Math.min(PANE_MAX_CEILING, Math.floor(viewportWidth * 0.58)))
}

const clampPane = (w: number, viewportWidth: number) => Math.max(PANE_MIN, Math.min(maxPaneWidth(viewportWidth), w))

/** Magnetic snap widths (360, 480, half the viewport), clamped to the allowed range, sorted and unique. */
export function paneSnapPoints(viewportWidth: number): number[] {
  const pts = [360, 480, Math.round(viewportWidth * 0.5)].map(p => clampPane(p, viewportWidth))
  return [...new Set(pts)].sort((a, b) => a - b)
}

/** Clamp a dragged width and snap it to the nearest snap point within `PANE_SNAP_THRESHOLD`. */
export function computeSnappedPaneWidth(rawWidth: number, viewportWidth: number): { width: number; snappedTo: number | null } {
  const width = clampPane(rawWidth, viewportWidth)
  let best: number | null = null
  for (const p of paneSnapPoints(viewportWidth)) {
    if (Math.abs(p - width) <= PANE_SNAP_THRESHOLD && (best == null || Math.abs(p - width) < Math.abs(best - width))) best = p
  }
  return best == null ? { width, snappedTo: null } : { width: best, snappedTo: best }
}

/** Keyboard steps for the right-anchored resizer: ←/→ ±24 (⇧ ±96), Home = min, End = max, Enter = reset. */
export function stepPaneWidth(currentWidth: number, key: string, shiftKey: boolean, viewportWidth: number): { width: number; reset?: boolean } | null {
  const step = shiftKey ? 96 : 24
  switch (key) {
    case 'ArrowLeft': return { width: clampPane(currentWidth + step, viewportWidth) }
    case 'ArrowRight': return { width: clampPane(currentWidth - step, viewportWidth) }
    case 'Home': return { width: PANE_MIN }
    case 'End': return { width: maxPaneWidth(viewportWidth) }
    case 'Enter': return { width: PANE_DEFAULT, reset: true }
    default: return null
  }
}

/** Overlay between 900 and 1439px, docked elsewhere; an explicit pin (true) / float (false) choice wins. */
export function resolvePaneMode(viewportWidth: number, pinnedPref: boolean | null): 'overlay' | 'docked' {
  if (pinnedPref === true) return 'docked'
  if (pinnedPref === false) return 'overlay'
  return viewportWidth >= PANE_OVERLAY_MIN_VP && viewportWidth <= PANE_OVERLAY_MAX_VP ? 'overlay' : 'docked'
}

const storeGet = (k: string) => { try { return localStorage.getItem(k) } catch { return null } }
const storeSet = (k: string, v: string | null) => {
  try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v) } catch { /* storage disabled */ }
}

/** Hide the right-hand Coordinator / Board pane until after scope approval. */
export function isBoardHiddenBeforeApproval(phase: string): boolean {
  return phase === 'consent' || phase === 'review'
}

function Workspace() {
  const { detail } = useRun()
  const nav = useNav()
  const overlays = useOverlays()
  const [paneW, setPaneW] = useState<number | null>(null)
  const [pinnedPref, setPinnedPref] = useState<boolean | null>(null)
  const [viewportW, setViewportW] = useState(1440)
  const [widenPrev, setWidenPrev] = useState<{ w: number | null } | null>(null)
  const [boardPeek, setBoardPeek] = useState(false)
  const [resizing, setResizing] = useState(false)
  const paneRef = useRef<HTMLElement>(null)
  const hideBoardBeforeApproval = isBoardHiddenBeforeApproval(detail.run.phase)
  useLayoutEffect(() => {
    const saved = Number(storeGet(PANE_KEY))
    if (saved >= PANE_MIN && saved <= PANE_MAX_CEILING) setPaneW(saved)
    const pin = storeGet(PANE_PIN_KEY)
    if (pin === '1' || pin === '0') setPinnedPref(pin === '1')
    const sync = () => setViewportW(window.innerWidth)
    sync()
    window.addEventListener('resize', sync)
    return () => window.removeEventListener('resize', sync)
  }, [])
  useGlobalShortcuts(hideBoardBeforeApproval)
  useBoardSeen()
  const View = VIEW_COMPONENTS[nav.view]
  // Board-first views keep the board as a docked companion column unless the operator chose to float it.
  const boardFirst = CHAT_FIRST_VIEWS.includes(nav.view) && !nav.sel
  const paneMode = pinnedPref == null && boardFirst ? 'docked' : resolvePaneMode(viewportW, pinnedPref)
  const overlay = paneMode === 'overlay'
  const width = clampPane(paneW ?? PANE_DEFAULT, viewportW)
  const hasContent = nav.sel != null || nav.chat
  // An overlay sheet only floats in while there is something to show: an item, the board, or a board-first view.
  const paneOpen = !nav.paneCollapsed && (!overlay || hasContent || boardPeek || boardFirst)
  const paneHidden = hideBoardBeforeApproval || !paneOpen

  // `]` / "Show panel" while an overlay sits idle opens the board instead of a silent collapse.
  const prev = useRef({ collapsed: nav.paneCollapsed, content: hasContent, open: paneOpen })
  useEffect(() => {
    const p = prev.current
    prev.current = { collapsed: nav.paneCollapsed, content: hasContent, open: paneOpen }
    if (p.content && !hasContent) setBoardPeek(false)
    if (!overlay || hideBoardBeforeApproval) return
    if (!p.collapsed && nav.paneCollapsed && !p.open) { nav.expandPane(); setBoardPeek(true) }
    else if (p.collapsed && !nav.paneCollapsed && !hasContent) setBoardPeek(true)
  })

  // Focus return: closing the pane while focus is inside it goes back to where the operator came from.
  const lastOutside = useRef<HTMLElement | null>(null)
  const focusInPane = useRef(false)
  useEffect(() => {
    const onFocus = (e: FocusEvent) => {
      const t = e.target
      if (!(t instanceof HTMLElement)) return
      focusInPane.current = !!paneRef.current?.contains(t)
      if (!focusInPane.current) lastOutside.current = t
    }
    document.addEventListener('focusin', onFocus)
    return () => document.removeEventListener('focusin', onFocus)
  }, [])
  const wasOpen = useRef(paneOpen)
  useLayoutEffect(() => {
    if (wasOpen.current && !paneOpen && focusInPane.current) {
      const active = document.activeElement
      const back = lastOutside.current
      if ((!active || active === document.body || paneRef.current?.contains(active)) && back?.isConnected) back.focus({ preventScroll: true })
      focusInPane.current = false
    }
    wasOpen.current = paneOpen
  }, [paneOpen])

  const resize = useCallback((w: number) => { setWidenPrev(null); setPaneW(w) }, [])
  const commit = useCallback((w: number) => storeSet(PANE_KEY, String(Math.round(w))), [])
  const reset = useCallback(() => { setWidenPrev(null); setPaneW(null); storeSet(PANE_KEY, null) }, [])
  const togglePin = useCallback(() => {
    const next = paneMode !== 'docked'
    setPinnedPref(next)
    storeSet(PANE_PIN_KEY, next ? '1' : '0')
  }, [paneMode])
  const toggleWiden = useCallback(() => {
    if (widenPrev) { setPaneW(widenPrev.w); setWidenPrev(null); return }
    setWidenPrev({ w: paneW })
    setPaneW(Math.min(maxPaneWidth(viewportW), Math.max(560, Math.round(viewportW * 0.5))))
  }, [widenPrev, paneW, viewportW])
  // Widening is for the evidence at hand: closing the item restores the previous width.
  useEffect(() => { if (!nav.sel && widenPrev) { setPaneW(widenPrev.w); setWidenPrev(null) } }, [nav.sel, widenPrev])
  const layout = useMemo(() => ({ mode: paneMode, pinned: paneMode === 'docked', width, widened: widenPrev != null, togglePin, toggleWiden }), [paneMode, width, widenPrev, togglePin, toggleWiden])

  const cols = overlay
    ? 'grid-cols-[232px_minmax(0,1fr)]'
    : paneHidden ? 'grid-cols-[232px_minmax(0,1fr)_0px]' : 'grid-cols-[232px_minmax(0,1fr)_var(--pane-w,404px)]'
  return <div
    className={cn('relative grid h-screen overflow-clip', cols, resizing && 'select-none')}
    style={{ ['--pane-w' as string]: width + 'px', ['--pane-inset' as string]: overlay && !paneHidden ? width + 'px' : '0px' }}
  >
    <Rail />
    <main className="relative flex min-h-0 min-w-0 flex-col overflow-clip bg-panel" aria-label="Run">
      <RunHeader />
      <RunBanners />
      <div key={nav.view} className="relative flex min-h-0 flex-1 flex-col" id="vh">
        <PanelErrorBoundary
          panelName={`${VIEWS.find(v => v.id === nav.view)?.label ?? nav.view} view`}
          resetKey={`${detail.run.id}:${nav.view}`}
          entityId={nav.view}
        >
          <View />
        </PanelErrorBoundary>
      </div>
    </main>
    {!hideBoardBeforeApproval && <aside
      ref={paneRef}
      className={cn(
        'flex min-h-0 min-w-0 flex-col overflow-clip [overflow-clip-margin:4px] bg-panel',
        overlay
          ? cn(
            'absolute inset-y-0 right-0 z-[20] w-[var(--pane-w,404px)] shadow-[-12px_0_32px_-12px_rgba(0,0,0,0.22),0_0_0_1px_var(--line)] transition-[translate,opacity] motion-reduce:translate-x-0 motion-reduce:transition-opacity motion-reduce:duration-150',
            paneOpen
              ? 'translate-x-0 opacity-100 duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]'
              : 'pointer-events-none translate-x-full opacity-0 duration-[180ms] ease-[cubic-bezier(0.2,0.8,0.2,1)]',
          )
          : cn(
            'relative border-l border-line transition-opacity duration-[var(--d2)] ease-kovo motion-reduce:transition-none',
            !paneOpen && 'pointer-events-none border-l-transparent opacity-0 duration-[var(--d1)]',
          ),
      )}
      aria-label="Inspector"
      aria-hidden={!paneOpen || undefined}
      inert={!paneOpen}
      data-pane-mode={paneMode}
      data-pane-width={Math.round(width)}
      data-pane-open={paneOpen ? '' : undefined}
    >
      {paneOpen && <Resizer width={width} viewportW={viewportW} onResize={resize} onCommit={commit} onReset={reset} onDraggingChange={setResizing} />}
      {overlay && paneOpen && nav.sel && <span data-testid="pane-overlay-edge-indicator" aria-hidden="true" className="pointer-events-none absolute inset-y-0 left-0 z-[4] w-0.5 bg-accent" />}
      <div id="paneInner" className="flex min-h-0 flex-1 flex-col">
        <PaneLayoutProvider value={layout}>
          <PaneContent />
        </PaneLayoutProvider>
      </div>
    </aside>}
    {overlays.scopeOpen && <ScopeOverlay />}
  </div>
}

/** Accessible, magnetic inspector resizer: drag (snaps to 360 / 480 / 50%), arrows, Home/End, Enter or double-click to reset. */
function Resizer({ width, viewportW, onResize, onCommit, onReset, onDraggingChange }: {
  width: number
  viewportW: number
  onResize: (w: number) => void
  onCommit: (w: number) => void
  onReset: () => void
  onDraggingChange: (dragging: boolean) => void
}) {
  const [drag, setDrag] = useState(false)
  const [snapped, setSnapped] = useState<number | null>(null)
  const start = useRef({ x: 0, w: 0 })
  const live = useRef(width)
  live.current = width
  useEffect(() => {
    onDraggingChange(drag)
    if (!drag) return
    const move = (e: PointerEvent) => {
      const r = computeSnappedPaneWidth(start.current.w + (start.current.x - e.clientX), viewportW)
      setSnapped(r.snappedTo)
      onResize(r.width)
    }
    const up = () => {
      setDrag(false)
      document.body.style.cursor = ''
      onCommit(live.current)
    }
    document.body.style.cursor = 'col-resize'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up) }
  }, [drag, viewportW, onResize, onCommit, onDraggingChange])
  const w = Math.round(width)
  const snappedTo = snapped != null && snapped === w ? snapped : null
  return <div
    className={cn(
      'absolute -left-[3px] bottom-0 top-0 z-[5] w-1.5 cursor-col-resize outline-none hover:bg-[linear-gradient(90deg,transparent_2px,var(--accent-line)_2px,var(--accent-line)_4px,transparent_4px)] focus-visible:outline-none focus-visible:bg-[linear-gradient(90deg,transparent_2px,var(--accent)_2px,var(--accent)_4px,transparent_4px)]',
      drag && (snappedTo != null
        ? 'bg-[linear-gradient(90deg,transparent_1.5px,var(--accent-line)_1.5px,var(--accent-line)_4.5px,transparent_4.5px)]'
        : 'bg-[linear-gradient(90deg,transparent_2px,var(--accent-line)_2px,var(--accent-line)_4px,transparent_4px)]'),
    )}
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize inspector"
    aria-valuemin={PANE_MIN}
    aria-valuemax={maxPaneWidth(viewportW)}
    aria-valuenow={w}
    aria-valuetext={`${w} pixels`}
    tabIndex={0}
    data-testid="pane-resizer"
    data-snapped={snappedTo != null ? String(snappedTo) : undefined}
    title="Drag to resize · ← → to step · double-click to reset"
    onPointerDown={e => {
      if (e.button !== 0) return
      e.preventDefault()
      start.current = { x: e.clientX, w: width }
      setSnapped(null)
      setDrag(true)
    }}
    onKeyDown={e => {
      const r = stepPaneWidth(width, e.key, e.shiftKey, viewportW)
      if (!r) return
      e.preventDefault()
      e.stopPropagation()
      e.nativeEvent.stopPropagation()
      setSnapped(null)
      if (r.reset) onReset()
      else { onResize(r.width); onCommit(r.width) }
    }}
    onDoubleClick={() => { setSnapped(null); onReset() }}
  >
    {drag && <span
      className={cn(
        'pointer-events-none absolute left-2.5 top-[52px] whitespace-nowrap rounded-[5px] px-1.5 py-0.5 font-mono text-[11px] leading-4 tabular-nums shadow-popover',
        snappedTo != null ? 'bg-accent text-accent-fg' : 'bg-fg text-panel',
      )}
      data-testid="pane-width-pill"
    >
      {w}px
    </span>}
  </div>
}

function PaneContent() {
  const { detail } = useRun()
  const nav = useNav()
  const sel = nav.sel
  const showChat = nav.chat || !sel || (CHAT_FIRST_VIEWS.includes(nav.view) && !sel)
  const key = showChat ? 'chat' : selKey(sel!)
  const Inspector = !showChat ? INSPECTORS[sel!.kind] ?? FallbackInspector : null
  const handleClose = () => {
    if (nav.chat) nav.closeChat()
    else if (nav.sel) nav.close()
    else nav.togglePane()
  }
  return <div key={key} className="flex min-h-0 min-w-0 flex-1 flex-col">
    <PanelErrorBoundary
      panelName={showChat ? 'Coordinator board' : 'Inspector panel'}
      resetKey={`${detail.run.id}:${key}`}
      entityId={key}
      onClose={handleClose}
    >
      {showChat ? <BoardPane /> : Inspector && <Inspector sel={sel!} />}
    </PanelErrorBoundary>
  </div>
}

/** Return the most recent unresolved `persona.auth_failed` or `persona.refresh_failed` event, if any. */
export function latestAuthIssue(events: readonly RunEvent[]): RunEvent | null {
  const byKey = new Map<string, RunEvent>()
  let lastAuthOkId = -1
  for (const ev of events) {
    if (ev.kind === 'persona.authenticated') {
      const key = typeof ev.detail?.handle === 'string' && ev.detail.handle
        ? ev.detail.handle
        : typeof ev.detail?.personaId === 'string' && ev.detail.personaId
          ? ev.detail.personaId
          : '*'
      byKey.set(key, ev)
      if (ev.id > lastAuthOkId) lastAuthOkId = ev.id
    } else if (ev.kind === 'persona.auth_failed' || ev.kind === 'persona.refresh_failed') {
      const key = typeof ev.detail?.handle === 'string' && ev.detail.handle
        ? ev.detail.handle
        : typeof ev.detail?.personaId === 'string' && ev.detail.personaId
          ? ev.detail.personaId
          : '*'
      byKey.set(key, ev)
    }
  }
  let latest: RunEvent | null = null
  for (const [key, ev] of byKey.entries()) {
    if (ev.kind !== 'persona.auth_failed' && ev.kind !== 'persona.refresh_failed') continue
    if (key === '*' && lastAuthOkId > ev.id) continue
    if (!latest || ev.id > latest.id) latest = ev
  }
  return latest
}

/** One-sentence budget-paused summary shared by the banner text and its title. */
export function budgetPausedCopy(r: { spentUsd: number; budgetUsd: number; spentRequests: number; budgetRequests: number }): string {
  const reqs = r.budgetRequests
    ? `${fmtN(r.spentRequests)} / ${fmtN(r.budgetRequests)} requests`
    : `${fmtN(r.spentRequests)} requests (uncapped)`
  return `Paused at budget: ${fmtUsd(r.spentUsd)} / ${fmtUsd(r.budgetUsd)} · ${reqs}. Partial report saved.`
}

/** Show the pinned top approval banner outside Queue and consent/review screens when active approvals wait. */
export function shouldShowApprovalBanner(input: {
  activeApprovalCount: number
  view: ViewId
  phase: string
}): boolean {
  if (input.activeApprovalCount <= 0) return false
  if (input.view === 'queue') return false
  if (isBoardHiddenBeforeApproval(input.phase)) return false
  return true
}

export function ApprovalBanner({
  approvals,
  submitting,
  onApprove,
  onDeny,
  onInspect,
  onReviewInQueue,
  onApproveAll,
}: {
  approvals: readonly Approval[]
  submitting: boolean
  onApprove: (ap: Approval) => void
  onDeny: (ap: Approval) => void
  onInspect: (ap: Approval) => void
  onReviewInQueue: () => void
  onApproveAll: () => void
}) {
  const count = approvals.length
  if (count <= 0) return null
  const first = approvals[0]!
  const target = `${first.method} ${host(first.origin)}${first.pathAndQuery}`
  const targetNode = <span className="font-mono text-[12px] text-fg">
    <span className="font-semibold text-warn">{first.method}</span> {host(first.origin)}
    <span className="text-fg-subtle">{first.pathAndQuery}</span>
  </span>
  return <div className="flex min-h-10 flex-none items-center gap-2.5 border-b border-accent-line bg-accent-soft py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted" role="status" aria-label="Pending approvals" data-testid="approval-banner">
    <span className="relative inline-flex size-2 flex-none" aria-hidden="true">
      <span className="absolute inset-0 animate-ping rounded-full bg-accent opacity-50 motion-reduce:animate-none" />
      <span className="relative inline-block size-2 rounded-full bg-accent" />
    </span>
    {count === 1 ? <>
      <span className="min-w-0 flex-1 truncate" title={`1 approval waiting · ${target}`}>
        <b className="font-medium text-fg">1 approval waiting</b> · {targetNode}
      </span>
      <button type="button" className={runBtn({ variant: 'primary', size: 'sm' })} data-testid="approval-banner-approve" onClick={() => onApprove(first)}>
        <Icon name="check" />Approve
      </button>
      <button type="button" className={runBtn({ variant: 'ghost', size: 'sm' })} data-testid="approval-banner-deny" onClick={() => onDeny(first)}>Deny</button>
      <button type="button" className={runBtn({ variant: 'default', size: 'sm' })} data-testid="approval-banner-inspect" onClick={() => onInspect(first)}>Inspect</button>
    </> : <>
      <span className="min-w-0 flex-1 truncate" title={`${count} approvals waiting · ${target} (+${count - 1} more)`}>
        <b className="font-medium text-fg">{count} approvals waiting</b> · {targetNode}
        <span className="ml-1.5 text-fg-subtle">(+{count - 1} more)</span>
      </span>
      <button type="button" className={runBtn({ variant: 'default', size: 'sm' })} data-testid="approval-banner-review" onClick={onReviewInQueue}>Review in Queue</button>
      <button type="button" className={runBtn({ variant: 'primary', size: 'sm' })} disabled={submitting} data-testid="approval-banner-approve-all" onClick={onApproveAll}>
        <Icon name="check" />{submitting ? `Approving ${count}…` : `Approve all (${count})`}
      </button>
    </>}
  </div>
}

export type LocalAuthProbeResult = 'ok' | 'expired' | 'unreachable'

/**
 * Lightweight `HEAD /_kovo/auth/status` check invoked when SSE enters `reconnecting` (`onerror`)
 * so an expired `kovo_local` session surfaces an explicit re-auth notice instead of spinning silently.
 */
export async function probeLocalAuthStatus(fetchImpl?: typeof fetch): Promise<LocalAuthProbeResult> {
  const fetcher = fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined)
  if (!fetcher) return 'unreachable'
  try {
    const res = await fetcher('/_kovo/auth/status', {
      method: 'HEAD',
      credentials: 'same-origin',
      cache: 'no-store',
    })
    if (res.status === 401) return 'expired'
    if (res.ok) return 'ok'
    return 'unreachable'
  } catch {
    return 'unreachable'
  }
}

/**
 * Pending approvals, budget-paused, auth-issue, model-missing, session-expired, reconnecting: crisp
 * one-line banners under the run line. On Overview the run hero owns the budget-paused state (and its
 * single "Raise budget" primary), so the budget banner only shows on the other views.
 */
function RunBanners() {
  const { detail, model, events, connection, pending } = useRun()
  const nav = useNav()
  const q = useDecisions()
  const [sessionExpired, setSessionExpired] = useState(false)
  const r = detail.run
  const authIssue = latestAuthIssue(events)

  useEffect(() => {
    if (connection === 'live') {
      setSessionExpired(false)
      return
    }
    if (connection !== 'reconnecting') return
    let cancelled = false
    void probeLocalAuthStatus().then(status => {
      if (!cancelled) setSessionExpired(status === 'expired')
    })
    return () => { cancelled = true }
  }, [connection])

  const showApprovalBanner = shouldShowApprovalBanner({
    activeApprovalCount: q.activePendingApprovals.length,
    view: nav.view,
    phase: r.phase,
  })
  const decideApproval = (ap: Approval, act: 'approve' | 'deny') => {
    q.decide('ap:' + ap.id, act, {
      command: approvalCommand(ap.id, act),
      message: `${ACTIONS[act].label} ${ap.method} ${host(ap.origin)}${ap.pathAndQuery}`,
    })
  }
  const bCls = 'flex min-h-10 flex-none items-center gap-2.5 border-b border-line py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted'
  const wCls = `${bCls} bg-warn-soft shadow-[inset_0_-1px_0_var(--warn-line)]`
  return <>
    {showApprovalBanner && <ApprovalBanner
      approvals={q.activePendingApprovals}
      submitting={pending > 0 || q.approvingAll}
      onApprove={ap => decideApproval(ap, 'approve')}
      onDeny={ap => decideApproval(ap, 'deny')}
      onInspect={ap => nav.open('queue', { kind: 'queue', id: 'ap:' + ap.id })}
      onReviewInQueue={() => nav.setView('queue')}
      onApproveAll={() => { void q.approveAllPending() }}
    />}
    {r.status === 'budget_paused' && nav.view !== 'overview' && <div className={wCls} role="status" aria-label="Budget paused" data-testid="budget-paused-banner">
      <Icon name="budget" className="text-warn" />
      <span className="num line-clamp-2 min-w-0 flex-1 whitespace-normal" title={budgetPausedCopy(r)}>
        <b className="font-medium text-fg">Paused at budget:</b> {budgetPausedCopy(r).slice('Paused at budget: '.length)}
      </span>
      <button type="button" data-rl-btn="" className={runBtn({ variant: 'primary' })} onClick={openBudgetPopover}>
        <Icon name="budget" />Raise budget
      </button>
    </div>}
    {authIssue && <div className={wCls} role="status" aria-label="Auth issue" data-testid="auth-issue-banner">
      <Icon name="lock" className="text-warn" />
      <span className="min-w-0 flex-1 truncate" title={authIssue.message}>
        <b className="font-medium text-fg">Auth issue.</b> {authIssue.message}
      </span>
      <Link className={runBtn()} to="/projects/$projectId" params={{ projectId: detail.project.id }} search={{ tab: 'personas' }}>
        Manage test accounts<Icon name="arrowR" />
      </Link>
    </div>}
    {model.needsModel && <div className={wCls} role="status">
      <Icon name="alert" className="text-warn" />
      <span className="min-w-0 flex-1"><b className="font-medium text-fg">Connect a model to continue.</b> No enabled model profile; settings bring you back here.</span>
      <Link className={runBtn()} to="/settings" search={{ runId: r.id }}>Set up model<Icon name="arrowR" /></Link>
    </div>}
    {sessionExpired && <div className={wCls} role="alert" aria-label="Local session expired" data-testid="session-expired-banner">
      <Icon name="lock" className="text-warn" />
      <span className="min-w-0 flex-1">
        <b className="font-medium text-fg">Local session expired.</b> Open the startup bootstrap URL from your Kovo terminal (or a device pairing link) to sign back in and resume live updates.
      </span>
      <button type="button" className={runBtn({ variant: 'default', size: 'sm' })} data-testid="session-expired-reload" onClick={() => { if (typeof window !== 'undefined') window.location.reload() }}>
        Reload
      </button>
    </div>}
    {connection === 'reconnecting' && !sessionExpired && <div className={`${bCls} bg-sunk`} role="status">
      <Icon name="activity" />
      <span className="min-w-0 flex-1">Reconnecting to Kovo… the view keeps the last data it had.</span>
    </div>}
  </>
}

/** Global keyboard model: ⌘K, ?, g+letter, 1–8, [ ], ⇧T, C, Esc stack. */
function useGlobalShortcuts(hideBoardBeforeApproval: boolean) {
  const nav = useNav()
  const pal = usePalette()
  const { runs, detail } = useRun()
  const { toggle } = useTheme()
  const switchBy = (d: number) => {
    const ids = runs.map(r => r.id)
    if (ids.length < 2) return
    let i = ids.indexOf(detail.run.id) + d
    i = (i + ids.length) % ids.length
    nav.switchRun(ids[i])
  }
  useShortcuts([
    { key: 'mod+k', allowInInput: true, run: () => (pal.isOpen ? pal.close() : pal.open()) },
    { key: '?', run: () => pal.openHelp() },
    { key: 'T', run: toggle },
    ...VIEWS.map((v, i) => ({ key: ['g ' + v.key, String(i + 1)], run: () => nav.setView(v.id) })),
    { key: '[', run: () => switchBy(-1) },
    { key: ']', run: () => { if (hideBoardBeforeApproval) return false; nav.togglePane() } },
    { key: 'c', run: () => { if (hideBoardBeforeApproval) return false; nav.openChat(null) } },
    { key: 'Escape', run: () => {
      if (nav.chat && nav.sel) { nav.closeChat(); return }
      if (nav.chat) { nav.closeChat(); return }
      if (nav.back()) return
      if (nav.sel) { nav.close(); return }
      return false
    } },
  ], { priority: 0 })
}
