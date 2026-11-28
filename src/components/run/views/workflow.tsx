// Workflow view (Agent W): execution trace in graph and list modes.
// Graph mode: phase columns of worker cards, handoff + causal edges, stacks,
// lineage highlight, camera, minimap, phase nav, replay. List mode, failure-first:
// a pinned "Needs attention" lane (failed workers grouped by signature, approvals,
// stalled workers), "Active now" capped at 6 rows, then grouped worker rows (each
// worker listed once). Inspectors: worker, stack, queued steps, step, graph digest.
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { isTerminalRunStatus } from '../../../server/run-status.ts'
import { Dropdown, FilterBox, Tabs } from '../controls.tsx'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, Kbd, KbdGroup, Seg, Tag } from '../display.tsx'
import { deriveRound0PipelineState, fmtN, host, isRound0ThreatModelWorker, plural, readRunUrlParam, syncRunUrlParam } from '../format.ts'
import { LiveDot, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { PHASE_LABEL, PHASE_ORDER, stLabel } from '../meta.ts'
import { ACTIVE_NOW_CAP, buildAttentionLane, capActiveNow, worstSeverity } from '../model.ts'
import type { AttentionGroup, Assignment } from '../model.ts'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import { Num } from '../num.tsx'
import { usePaletteCommands } from '../palette.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { cn, runBtn, runDdItem, RW } from '../tw.ts'
import { isLive, QUEUE_ID, setExpanded, useWorkflowLayout } from './workflow-layout.ts'

// The graph canvas is an opt-in mode (~45 KB); load it on demand so the run route chunk stays inside its budget.
const WorkflowGraph = lazy(() => import('./workflow-graph.tsx').then(m => ({ default: m.WorkflowGraph })))
// Inspectors (worker trace + timeline rail, stack, steps, digest) load on first selection, one shared chunk.
let inspectorsModule: ReturnType<typeof importInspectors> | null = null
function importInspectors() { return import('./workflow-inspector.tsx') }
const loadInspectors = () => (inspectorsModule ??= importInspectors())
// Start fetching on the client as soon as the workflow view is evaluated, so hydrating a
// server-rendered inspector (deep link with `sel=worker:…`) never waits on a cold chunk.
if (typeof window !== 'undefined') void loadInspectors()
type InspectorName = 'WorkerInspector' | 'StackInspector' | 'StepsInspector' | 'StepInspector' | 'DigestInspector'
function lazyInspector(name: InspectorName) {
  const Lazy = lazy(() => loadInspectors().then(m => ({ default: m[name] as (props: InspectorProps) => ReactNode })))
  return function LazyInspector(props: InspectorProps) {
    return <Suspense fallback={<div className="min-h-0 flex-1" aria-busy="true" aria-label="Loading inspector" />}><Lazy {...props} /></Suspense>
  }
}

type Filter = 'all' | 'live' | 'complete' | 'findings' | 'failed'
type Mode = 'graph' | 'list'
const isWorkflowMode = (v: string | null): v is Mode => v === 'graph' || v === 'list'
type Group = 'phase' | 'step' | 'status' | 'none'
const GROUPS: [Group, string][] = [['phase', 'Phase'], ['step', 'Plan step'], ['status', 'Status'], ['none', 'None']]
const ICON_SLOT = 'inline-flex size-3.5 flex-none items-center justify-center'
const PILL = 'inline-flex h-[17px] flex-none items-center gap-1 rounded-[9px] px-1.5 text-[11px] font-medium tabular-nums shadow-[inset_0_0_0_1px_var(--line-2)]'

export function WorkflowView() {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const L = useWorkflowLayout()
  const runId = detail.run.id
  const terminal = isTerminalRunStatus(detail.activity?.lifecycle ?? detail.run.status) || detail.run.phase === 'complete'
  const [mode, setModeState] = useViewState<Mode>('wf.mode', 'list')
  const [filter, setFilter] = useViewState<Filter>('wf.filter', 'all')
  const [query, setQuery] = useViewState('wf.q', '')
  const [replay, setReplay] = useState(false)
  // Graph opened from the keyboard (L / palette) renders settled, without the entrance (A-137).
  const [viaKeyboard, setViaKeyboard] = useState(false)
  const setMode = useCallback((next: Mode) => {
    setModeState(next)
    syncRunUrlParam('mode', next === 'list' ? null : next)
  }, [setModeState])
  useEffect(() => {
    const fromUrl = readRunUrlParam('mode')
    if (isWorkflowMode(fromUrl)) {
      if (fromUrl !== mode) setModeState(fromUrl)
    } else if (mode !== 'list') {
      syncRunUrlParam('mode', mode)
    }
    const onPop = () => {
      const u = readRunUrlParam('mode')
      setModeState(isWorkflowMode(u) ? u : 'list')
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const filterRef = useRef<HTMLInputElement>(null)
  const assignments = detail.assignments

  // ---- filters + search
  const tabs = useMemo(() => {
    const t: Record<Filter, number> = { all: assignments.length, live: 0, complete: 0, findings: 0, failed: 0 }
    for (const a of assignments) {
      if (!terminal && isLive(a)) t.live++
      if (a.status === 'complete') t.complete++
      if (a.status === 'failed') t.failed++
      if ((model.workerFindings.get(a.id) ?? []).length) t.findings++
    }
    const all: [Filter, string][] = [['all', 'All'], ['live', 'Active'], ['complete', 'Complete'], ['findings', 'With findings'], ['failed', 'Failed']]
    return all.filter(([k]) => k === 'all' || t[k]).map(([k, l]) => ({ k, l, n: t[k] }))
  }, [assignments, model, terminal])
  const effFilter: Filter = tabs.some(t => t.k === filter) ? filter : 'all'
  // Failed and Active tabs never fold into "More" (A-102).
  const pinnedTabs = useMemo(() => tabs.filter(t => t.k === 'failed' || t.k === 'live').map(t => t.k), [tabs])
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  const matches = useCallback((a: Assignment) => {
    if (effFilter === 'live' && (terminal || !isLive(a))) return false
    if (effFilter === 'complete' && a.status !== 'complete') return false
    if (effFilter === 'failed' && a.status !== 'failed') return false
    if (effFilter === 'findings' && !(model.workerFindings.get(a.id) ?? []).length) return false
    if (!terms.length) return true
    const hay = (a.title + ' ' + a.objective + ' ' + (a.outcome ?? '') + ' ' + a.sourceOrigins.join(' ') + ' ' + a.phase).toLowerCase()
    return terms.every(t => hay.includes(t))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effFilter, model, terminal, terms.join(' ')])
  const nomatch = useMemo(() => {
    const out = new Set<string>()
    for (const n of L.nodes) {
      const ok = n.kind === 'worker' ? matches(n.a!) : n.kind === 'stack' ? n.members!.some(matches)
        : effFilter === 'all' && (!terms.length || n.steps!.some(s => terms.every(t => (s.title + ' ' + s.hypothesis).toLowerCase().includes(t))))
      if (!ok) out.add(n.id)
    }
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [L, matches, effFilter])

  // ---- selection ↔ graph node
  const sel = nav.sel
  const selWorker = sel?.kind === 'worker' ? model.workerById.get(sel.id) : undefined
  // cross-links to a stacked worker auto-expand its stack
  useEffect(() => {
    if (!selWorker) return
    const g = L.stacks.of.get(selWorker.id)
    if (g) setExpanded(runId, g, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selWorker?.id, runId])
  const selId = !sel ? null
    : sel.kind === 'worker' ? (L.byId.has(sel.id) ? sel.id : L.stacks.of.get(sel.id) ?? null)
      : sel.kind === 'stack' ? (L.byId.has(sel.id) ? sel.id : null)
        : sel.kind === 'steps' || sel.kind === 'step' ? (L.byId.has(QUEUE_ID) ? QUEUE_ID : null) : null
  const focusSet = useMemo(() => {
    if (sel?.kind !== 'digest') return null
    const dg = detail.digests.find(d => d.id === sel.id)
    if (!dg) return null
    const rep = (id: string) => (L.byId.has(id) ? id : L.stacks.of.get(id) ?? id)
    return new Set(dg.coveredAssignmentIds.map(rep).filter(id => L.byId.has(id)))
  }, [sel, detail.digests, L])

  const select = useCallback((id: string | null) => {
    if (!id) return nav.select(null)
    if (id === QUEUE_ID) return nav.select({ kind: 'steps', id: 'queued' })
    if (L.stacks.groups.has(id)) return nav.select({ kind: 'stack', id })
    nav.select({ kind: 'worker', id })
  }, [nav, L])
  const expand = useCallback((gid: string, on: boolean) => {
    setExpanded(runId, gid, on)
    if (!on && sel?.kind === 'worker' && L.stacks.of.get(sel.id) === gid) nav.select({ kind: 'stack', id: gid })
    if (on && sel?.kind === 'stack' && sel.id === gid) nav.select(null)
  }, [runId, sel, L, nav])

  // ---- replay, mode, keys, palette
  const startReplay = useCallback(() => {
    if (!assignments.length) return
    setMode('graph')
    setReplay(r => !r)
  }, [assignments.length, setMode])
  useShortcuts([
    { key: 'l', run: () => { setReplay(false); setViaKeyboard(true); setMode(mode === 'graph' ? 'list' : 'graph') } },
    { key: 'R', run: startReplay },
    { key: 'Escape', run: () => { if (!replay) return false; setReplay(false) } },
  ])
  usePaletteCommands([
    { id: 'wf.replay', section: 'Actions', label: replay ? 'Stop the workflow replay' : 'Replay the run in the workflow graph', icon: 'replay', keys: ['⇧', 'R'], run: startReplay },
    { id: 'wf.mode', section: 'Actions', label: mode === 'graph' ? 'Show workers as a list' : 'Show the workflow graph', icon: mode === 'graph' ? 'list' : 'graph', keys: ['L'], run: () => { setViaKeyboard(true); setMode(mode === 'graph' ? 'list' : 'graph') } },
  ])

  const firstMatch = () => {
    const ordered = L.nodes.filter(n => !nomatch.has(n.id) && n.kind !== 'queue').sort((a, b) => a.x - b.x || a.y - b.y)
    if (mode === 'list') {
      const a = assignments.filter(matches).sort((x, y) => x.createdAt - y.createdAt)[0]
      if (a) nav.select({ kind: 'worker', id: a.id })
    } else if (ordered[0]) {
      const n = ordered[0]
      if (n.kind === 'stack') { const m = n.members!.find(matches); if (m) nav.select({ kind: 'worker', id: m.id }) }
      else select(n.id)
    }
    filterRef.current?.blur()
  }

  const modeBtnCls = (on: boolean) => cn(
    'inline-flex h-[22px] cursor-pointer items-center justify-center gap-[5px] rounded-[4px] border-0 px-2 font-sans text-[12px] font-medium transition-[background-color,color,box-shadow] duration-[var(--d1)] @max-[760px]/wftb:px-[7px]',
    on
      ? 'bg-raise text-fg shadow-[0_0_0_1px_var(--line-2),0_1px_2px_rgba(0,0,0,.05)] hover:bg-raise'
      : 'bg-transparent text-fg-muted shadow-none hover:bg-transparent hover:text-fg',
  )

  const toolbar = <div className={cn(RW.toolbar, 'relative @container/wftb')} data-tb="workflow">
    <Tabs tabs={tabs.map(t => [t.k, t.l, t.n] as [Filter, string, number])} value={effFilter} onChange={setFilter} label="Filter workers" pinned={pinnedTabs} />
    <FilterBox
      ref={filterRef}
      value={query}
      onChange={setQuery}
      onEnter={firstMatch}
      label="Filter workers"
      className="flex-none @max-[760px]/wftb:w-24"
    />
    {mode === 'list' && <GroupMenu />}
    {detail.digests.length > 0 && <DigestMenu />}
    <button
      type="button"
      className={runBtn({ variant: replay ? 'ghostOn' : 'ghost' })}
      title="Replay the run (⇧R)"
      onClick={startReplay}
      disabled={!assignments.length}
    >
      <Icon name="replay" /><span className="@max-[760px]/wftb:hidden">Replay</span>
    </button>
    <div
      className="inline-flex h-[26px] flex-none items-center rounded-control bg-sunk p-0.5 shadow-[inset_0_0_0_1px_var(--line)]"
      title="List or graph (L)"
      role="radiogroup"
    >
      <button type="button" role="radio" aria-label="List" aria-checked={mode === 'list'} className={modeBtnCls(mode === 'list')} onClick={() => { setReplay(false); setMode('list') }}>
        <Icon name="list" /><span className="@max-[760px]/wftb:hidden">List</span>
      </button>
      <button type="button" role="radio" aria-label="Graph" aria-checked={mode === 'graph'} className={modeBtnCls(mode === 'graph')} onClick={() => { setViaKeyboard(false); setMode('graph') }}>
        <Icon name="graph" /><span className="@max-[760px]/wftb:hidden">Graph</span>
      </button>
    </div>
  </div>

  if (!assignments.length) {
    return <>{toolbar}<EmptyState icon="workers" title="No workers dispatched"
      action={detail.run.status === 'waiting' ? <button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
      {workflowEmptyCopy(detail.run.status)}
    </EmptyState></>
  }
  return <>
    {toolbar}
    {mode === 'graph'
      ? <Suspense fallback={<div className="relative min-h-0 flex-1 bg-canvas" aria-busy="true" aria-label="Loading workflow graph" />}>
        <WorkflowGraph L={L} selId={selId} focusSet={focusSet} nomatch={nomatch} onSelect={select} onExpand={expand}
          onReport={() => nav.setView('report')} replay={replay} onReplayClose={() => setReplay(false)} skipEntrance={viaKeyboard} />
      </Suspense>
      : <WorkerList matches={matches} terminal={terminal} />}
  </>
}

/** Empty-workflow body copy that matches the run status (A-134). */
function workflowEmptyCopy(status: string): string {
  if (status === 'complete') return 'This run finished without dispatching workers.'
  if (status === 'waiting') return 'The coordinator plans chain steps after scope consent, then dispatches sandboxed workers.'
  return 'No workers have been dispatched yet. The coordinator plans chain steps first, then dispatches sandboxed workers.'
}

/** Static live marker for pinned rows; the single pulse lives in the Active-now header (A-130). */
function StaticLiveDot({ paused }: { paused: boolean }) {
  return <span className={cn('mx-[3px] inline-block size-2 flex-none rounded-full', paused ? 'bg-warn' : 'bg-accent')} aria-hidden="true" />
}

/** "{n} threat model · {m} investigation" breakdown for the Active-now header (A-128). */
function phaseBreakdown(items: readonly Assignment[]): string {
  const by = new Map<string, number>()
  for (const a of items) by.set(a.phase, (by.get(a.phase) ?? 0) + 1)
  return [...by.entries()]
    .sort((a, b) => (PHASE_ORDER[a[0]] ?? 9) - (PHASE_ORDER[b[0]] ?? 9))
    .map(([p, n]) => `${fmtN(n)} ${(PHASE_LABEL[p] ?? p).toLowerCase()}`)
    .join(' · ')
}

// ---------------------------------------------------------------- toolbar menus

function GroupMenu() {
  const [group, setGroup] = useViewState<Group>('wf.group', 'phase')
  return <Dropdown icon="sliders" title="Display options (⇧G cycles grouping)"
    label={<><span className="text-fg-subtle @max-[760px]/wftb:hidden">Group</span><span>{GROUPS.find(g => g[0] === group)?.[1]}</span></>}>
    <div className={RW.ddSec}>Grouping<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
    <Seg<Group> value={group} onChange={setGroup} fullWidth options={GROUPS.map(([value, label]) => ({ value, label }))} />
  </Dropdown>
}

/** Memory summaries (saved workspace snapshots of older facts). */
function DigestMenu() {
  const { detail } = useRun()
  const nav = useNav()
  const ds = detail.digests
  const active = ds.filter(d => d.active).length
  return <Dropdown icon="archive" title="Memory summaries" menuClassName="w-[320px] p-1.5"
    btnClassName={runBtn({ variant: nav.sel?.kind === 'digest' ? 'ghostOn' : 'ghost' })}
    label={<><span className="text-fg-subtle @max-[760px]/wftb:hidden">Summaries</span><span className="tabular-nums">{active || ds.length}</span></>}>
    {close => <>
      <div className={cn(RW.ddSec, 'px-2 py-1.5')}>Memory summaries<span className="ml-auto font-normal tabular-nums">{active} active · {ds.length} total</span></div>
      {ds.map(d => <button
        key={d.id}
        type="button"
        role="menuitem"
        className={cn(runDdItem({ active: nav.sel?.kind === 'digest' && nav.sel.id === d.id }), 'h-auto min-h-8 py-[5px]')}
        onClick={() => { close(); nav.select({ kind: 'digest', id: d.id }) }}
      >
        <span className="min-w-0 truncate">Round {d.roundNo} · {d.level}{!d.active && <span className="text-fg-subtle"> · superseded</span>}</span>
        <span className="ml-auto flex-none text-fg-subtle tabular-nums">{plural(d.coveredFactIds.length, 'fact')} · {d.coveredAssignmentIds.length} w</span>
      </button>)}
      <p className="mx-2 mb-0.5 mt-1.5 text-[11.5px] text-fg-subtle">Highlights covered workers.</p>
    </>}
  </Dropdown>
}

// ---------------------------------------------------------------- list mode

const ATTENTION_ICON: Record<AttentionGroup['kind'], 'alert' | 'shield' | 'pause'> = { failed: 'alert', approval: 'shield', stalled: 'pause' }
const ATTENTION_ACTION: Record<AttentionGroup['kind'], string> = { failed: 'Inspect', approval: 'Review approval', stalled: 'Inspect' }

/** "4 failed · 1 awaiting approval · 1 stalled" for the Needs-attention header. */
function attentionBreakdown(groups: readonly AttentionGroup[]): string {
  const n = { failed: 0, approval: 0, stalled: 0 }
  for (const g of groups) n[g.kind] += g.workers.length
  return [n.failed && `${fmtN(n.failed)} failed`, n.approval && `${fmtN(n.approval)} awaiting approval`, n.stalled && `${fmtN(n.stalled)} stalled`].filter(Boolean).join(' · ')
}

function WorkerList({ matches, terminal }: { matches: (a: Assignment) => boolean; terminal: boolean }) {
  const { events, detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const [group, setGroup] = useViewState<Group>('wf.group', 'phase')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('wf.collapsed', {})
  const [activeAll, setActiveAll] = useViewState('wf.activeAll', false)
  const [attnOpen, setAttnOpen] = useViewState<Record<string, boolean>>('wf.attnOpen', {})
  const runStatus = detail.activity?.lifecycle ?? detail.run.status
  const items = useMemo(() => model.detail.assignments.filter(matches).slice().sort((a, b) => a.createdAt - b.createdAt), [model, matches])
  // Failure-first: everything that needs a human sits in its own lane and is not repeated below.
  const lane = useMemo(() => buildAttentionLane(items, terminal ? 'complete' : runStatus), [items, terminal, runStatus])
  const { activeItems, restItems } = useMemo(() => {
    const rest: Assignment[] = []
    const active: Assignment[] = []
    for (const a of items) {
      if (lane.ids.has(a.id)) continue
      if (!terminal && isLive(a)) active.push(a)
      else rest.push(a)
    }
    active.sort((a, b) => Number(a.status !== 'running') - Number(b.status !== 'running') || a.createdAt - b.createdAt)
    return { activeItems: active, restItems: rest }
  }, [items, terminal, lane])
  const activeView = capActiveNow(activeItems, activeAll)
  const attentionN = lane.ids.size
  const laneOpen = (g: AttentionGroup) => g.workers.length === 1 || !!attnOpen[g.key]
  const laneIds = lane.groups.flatMap(g => (laneOpen(g) ? g.workers.map(a => a.id) : []))
  const groups = useMemo(() => {
    if (group === 'none') return null
    const by = new Map<string, Assignment[]>()
    for (const a of restItems) {
      const k = group === 'phase' ? a.phase : group === 'status' ? a.status : a.stepId ?? '_none'
      by.set(k, [...(by.get(k) ?? []), a])
    }
    const keys = [...by.keys()]
    const seq = (k: string) => model.stepById.get(k)?.seq ?? -1
    keys.sort((a, b) => group === 'phase' ? (PHASE_ORDER[a] ?? 9) - (PHASE_ORDER[b] ?? 9) : group === 'step' ? seq(a) - seq(b) : a.localeCompare(b))
    return keys.map(k => {
      const step = group === 'step' ? model.stepById.get(k) : undefined
      const label = group === 'phase' ? PHASE_LABEL[k] ?? k : group === 'status' ? stLabel(k) : step ? '#' + step.seq + ' ' + step.title : 'Unplanned'
      const glyph: ReactNode = group === 'phase' ? <span className="flex text-fg-subtle"><Icon name="workers" /></span> : <StatusGlyph status={group === 'status' ? k : step?.status ?? 'complete'} />
      return { key: k, label, glyph, items: by.get(k)! }
    })
  }, [restItems, group, model])
  const ck = (k: string) => group + ':' + k
  const restIds = groups ? groups.flatMap(g => (collapsed[ck(g.key)] ? [] : g.items.map(a => a.id))) : restItems.map(a => a.id)
  const ids = [...laneIds, ...activeView.shown.map(a => a.id), ...restIds]
  const { index } = useListNav({ ids, kind: 'worker' })
  useShortcuts([{ key: 'G', run: () => setGroup(GROUPS[(GROUPS.findIndex(g => g[0] === group) + 1) % GROUPS.length][0]) }])
  const listRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (index < 0) return
    listRef.current?.querySelector(`[data-id="${CSS.escape(ids[index])}"]`)?.scrollIntoView({ block: 'nearest' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index])
  const row = (a: Assignment, lanePin?: 'active' | 'attention') => {
    const pinned = lanePin != null
    const fs = model.workerFindings.get(a.id) ?? []
    const nfa = (model.factsByWorker.get(a.id) ?? []).length
    const pct = a.maxTurns ? Math.min(100, a.turnsUsed / a.maxTurns * 100) : 0
    const cur = nav.sel?.kind === 'worker' && nav.sel.id === a.id
    const live = !terminal && isLive(a)
    const r0 = isRound0ThreatModelWorker(a) ? deriveRound0PipelineState({ assignment: a, detail: model.detail, events }) : null
    return <div
      key={a.id}
      className={cn(
        RW.row,
        lanePin === 'active' && 'bg-panel/85 border-l-accent last:border-b-0 hover:bg-panel',
        lanePin === 'attention' && 'bg-panel/85 border-l-danger last:border-b-0 hover:bg-panel',
        cur && RW.rowCur,
      )}
      data-id={a.id}
      data-n={a.id}
      data-wf-row=""
      onClick={() => nav.select({ kind: 'worker', id: a.id })}
    >
      <span className={ICON_SLOT} title={stLabel(a.status)}>
        {live ? <StaticLiveDot paused={a.status !== 'running'} /> : <StatusGlyph status={a.status} />}
      </span>
      <span className={cn('min-w-[30%] flex-1 truncate text-fg', pinned && 'font-medium')} title={a.title}>{a.title}</span>
      {pinned && a.status !== 'failed' && <Tag tone={a.status === 'running' ? 'accent' : 'warn'} className="flex-none">{stLabel(a.status)}</Tag>}
      {fs.length > 0 && <span className={cn(PILL, 'bg-panel text-fg')} title="Findings"><SevGlyph sev={worstSeverity(fs)} />{fmtN(fs.length)}</span>}
      {!r0 && nfa > 0 && <span className={cn(PILL, 'bg-sunk text-fg-muted')}>{fmtN(nfa)} facts</span>}
      {r0 ? <>
        <Tag tone={live ? 'accent' : 'solid'}>{r0.stageShort}</Tag>
        {r0.counts.totalHosts > 0 && <span className="flex-none text-[12px] text-fg-subtle tabular-nums">{r0.counts.mappedHosts}/{r0.counts.totalHosts} hosts</span>}
      </> : <>
        {(lanePin === 'active' || (!pinned && group !== 'phase')) && <span className="min-w-0 max-w-[140px] shrink truncate"><Tag>{PHASE_LABEL[a.phase] ?? a.phase}</Tag></span>}
        {/* Attention rows drop the host column so the status tag and inline action always fit. */}
        {lanePin === 'attention' && a.status !== 'failed' ? null
          : a.status === 'failed' && a.outcome
            ? <span className="min-w-0 max-w-[260px] shrink truncate text-[12px] text-danger" title={a.outcome} data-wf-reason="">{a.outcome}</span>
            : <span className="w-[120px] flex-none truncate text-right font-mono text-[12px] text-fg-subtle @max-[720px]/wfl:hidden">{host(a.sourceOrigins[0] ?? '')}</span>}
        <span className="flex min-w-[84px] flex-none items-center justify-end gap-1.5 whitespace-nowrap text-fg-subtle tabular-nums" title="Turns used" data-wf-turns="">
          <span className="relative h-[3px] w-8 flex-none overflow-hidden rounded bg-line-2"><i className={cn('absolute inset-y-0 left-0', live ? 'bg-accent' : 'bg-fg-subtle')} style={{ width: pct + '%' }} /></span>
          <Num value={a.turnsUsed} kind="turns" max={a.maxTurns} />/<Num value={a.maxTurns} kind="turns" />
        </span>
      </>}
      <span className="min-w-[72px] flex-none whitespace-nowrap text-right text-fg-subtle tabular-nums" title="Requests" data-wf-req=""><Num value={r0 ? r0.counts.requests : a.requestsUsed} kind="count" unit="req" /></span>
      {lanePin === 'attention' && a.status === 'waiting_approval' && <button
        type="button"
        className={cn(runBtn({ variant: 'ghost', size: 'xs' }), 'flex-none')}
        onClick={e => { e.stopPropagation(); nav.setView('queue') }}
      >Review approval</button>}
    </div>
  }
  /** Grouped failure signature: one 36px row "signature ×N" with an inline action and expand toggle. */
  const groupRow = (g: AttentionGroup) => {
    const open = !!attnOpen[g.key]
    const req = g.workers.reduce((s, a) => s + a.requestsUsed, 0)
    const act = () => (g.kind === 'approval' ? nav.setView('queue') : nav.select({ kind: 'worker', id: g.workers[0]!.id }))
    return <div key={g.key} data-attention-group={g.kind} data-attention-count={g.workers.length}>
      <div className={cn(RW.row, 'bg-panel/85 border-l-danger pr-3 hover:bg-panel')} data-attention-row="">
        <span className={cn(ICON_SLOT, g.kind === 'failed' ? 'text-danger' : 'text-warn')}><Icon name={ATTENTION_ICON[g.kind]} size={13} /></span>
        <span className={cn('min-w-0 flex-1 truncate text-[12.5px]', g.kind === 'failed' ? 'text-danger' : 'text-fg')} title={g.reason} data-wf-reason="">{g.reason}</span>
        <span className={cn(PILL, 'bg-danger-soft text-danger')} data-attention-multiplier="" title={plural(g.workers.length, 'worker')}>×{fmtN(g.workers.length)}</span>
        <span className="min-w-[72px] flex-none whitespace-nowrap text-right text-fg-subtle tabular-nums" title="Requests"><Num value={req} kind="count" compact unit="req" /></span>
        <button type="button" className={cn(runBtn({ variant: 'ghost', size: 'xs' }), 'flex-none')} onClick={act}>{ATTENTION_ACTION[g.kind]}</button>
        <button
          type="button"
          className={cn(runBtn({ variant: 'ghost', size: 'xs' }), 'flex-none px-1')}
          aria-expanded={open}
          aria-label={`${open ? 'Hide' : 'Show'} ${plural(g.workers.length, 'worker')} with this signature`}
          onClick={() => setAttnOpen(o => ({ ...o, [g.key]: !open }))}
        >
          <Icon name="chev" className={cn('transition-transform duration-[var(--d2)] ease-kovo motion-reduce:transition-none', !open && '-rotate-90')} />
        </button>
      </div>
      {open && g.workers.map(a => row(a, 'attention'))}
    </div>
  }
  if (!items.length) return <EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState>
  return <div className={cn(RW.list, '@container/wfl')} ref={listRef} tabIndex={-1} role="region" aria-label="Worker list">
    {attentionN > 0 && (
      <section data-testid="workflow-attention-section" aria-label={`Needs attention (${attentionN})`} className="mx-3 mt-2.5 overflow-hidden rounded-lg border border-[color-mix(in_oklch,var(--danger)_35%,transparent)] bg-danger-soft/40">
        <div className="flex h-8 items-center gap-2 border-b border-[color-mix(in_oklch,var(--danger)_25%,transparent)] bg-danger-soft px-3 text-[12px] font-medium text-fg">
          <Icon name="alert" size={13} className="flex-none text-danger" />
          <span className="flex-none tabular-nums">Needs attention ({fmtN(attentionN)})</span>
          <span className="ml-auto min-w-0 truncate text-[11.5px] font-normal text-fg-muted tabular-nums" data-wf-attention-breakdown="">{attentionBreakdown(lane.groups)}</span>
        </div>
        {lane.groups.map(g => (g.workers.length === 1 ? row(g.workers[0]!, 'attention') : groupRow(g)))}
      </section>
    )}
    {activeItems.length > 0 && (
      <section data-testid="workflow-active-section" aria-label={`Active now (${activeItems.length})`} className="mx-3 my-2.5 overflow-hidden rounded-lg border border-accent-line bg-accent-soft/45">
        <div className="flex h-8 items-center gap-2 border-b border-accent-line/60 bg-accent-soft px-3 text-[12px] font-medium text-fg">
          <LiveDot paused={!activeItems.some(a => a.status === 'running')} />
          <span className="flex-none tabular-nums">Active now ({fmtN(activeItems.length)})</span>
          <span className="ml-auto min-w-0 truncate text-[11.5px] font-normal text-fg-muted tabular-nums" data-wf-active-breakdown="">{phaseBreakdown(activeItems)}</span>
        </div>
        {activeView.shown.map(a => row(a, 'active'))}
        {activeItems.length > ACTIVE_NOW_CAP && <button
          type="button"
          className="flex h-auto min-h-8 w-full cursor-pointer items-center justify-center gap-1 whitespace-normal rounded-none border-0 border-t border-accent-line/60 bg-transparent px-3 py-1.5 text-[12px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-accent-soft hover:text-fg"
          aria-expanded={activeAll}
          data-testid="workflow-active-toggle"
          onClick={() => setActiveAll(v => !v)}
        >
          {activeAll ? 'Show fewer' : `Show all ${fmtN(activeItems.length)}`}<Icon name={activeAll ? 'chevU' : 'chevD'} size={11} />
        </button>}
      </section>
    )}
    {groups ? groups.map(g => {
      const col = !!collapsed[ck(g.key)]
      const tu = g.items.reduce((s, a) => s + a.turnsUsed, 0), req = g.items.reduce((s, a) => s + a.requestsUsed, 0)
      return <div key={g.key}>
        <div className={RW.ghead} role="button" tabIndex={0} aria-expanded={!col}
          onClick={() => setCollapsed(c => ({ ...c, [ck(g.key)]: !col }))}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCollapsed(c => ({ ...c, [ck(g.key)]: !col })) } }}>
          <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', col && '-rotate-90')} />
          <span className={ICON_SLOT}>{g.glyph}</span>
          <span>{g.label}</span>
          <span className="font-normal text-fg-subtle tabular-nums">{fmtN(g.items.length)}</span>
          <span className="ml-auto flex items-center gap-1 font-normal text-fg-subtle tabular-nums"><Num value={tu} kind="turns" unit="turns" /> · <Num value={req} kind="count" unit="req" /></span>
        </div>
        {!col && g.items.map(a => row(a))}
      </div>
    }) : restItems.map(a => row(a))}
    <div className={cn(RW.listnote, 'gap-1')}><Kbd>L</Kbd> graph · <Kbd>⇧</Kbd><Kbd>G</Kbd> grouping</div>
  </div>
}

// ---------------------------------------------------------------- inspectors

/** Inspectors this view owns, keyed by selection kind. */
export const workflowInspectors: InspectorMap = {
  worker: lazyInspector('WorkerInspector'),
  stack: lazyInspector('StackInspector'),
  steps: lazyInspector('StepsInspector'),
  step: lazyInspector('StepInspector'),
  digest: lazyInspector('DigestInspector'),
}
