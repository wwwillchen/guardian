// Findings view (A's list inside F's frame), owned by Agent Q.
//
// The collapsible verdict strip (B's headline) sits above a toolbar with
// status tabs, a quiet low-priority fold (Out of scope · Suppressed), a `/` filter and a
// display menu (group by severity / fix status / category / origin / status / none,
// ordering, Comfortable / Compact density). Tabs, group tallies and rows all come from the
// single triage-aware projection (`projectTriagedFindings`), so tab totals equal the headline's
// counts; suppressed findings never land in an active severity group. Every row leads with a
// fixed 72px severity column. Confirmed is the quiet outlined check; accent means selection only.
// Long lists are windowed.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ReactNode, RefObject } from 'react'
import type { OperatorTriage, OperatorTriageStatus } from '../../../actions-triage.ts'
import { ACTIVE_TRIAGE_BUCKETS, indexFindingFixStates, projectTriagedFindings, runFindingsScopeContext } from '../../../findings-view.ts'
import type { FindingFixState, FindingTriageBucket, TriagedFindingRow } from '../../../findings-view.ts'
import { Dropdown, FilterBox, Tabs } from '../controls.tsx'
import { canOfferResumeButton } from '../../../server/run-status.ts'
import { useRun, useRunModel, useVerdict } from '../data.tsx'
import { EmptyState, FindingTitle, KbdGroup, Seg, Tag } from '../display.tsx'
import { host } from '../format.ts'
import { FIX_STATE_LABEL, FixStatePill, SevCell, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { prettyCat, SEV_LABEL, SEV_ORDER } from '../meta.ts'
import type { FindingRow } from '../model.ts'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import type { InspectorMap } from '../pane.tsx'
import { usePaletteCommands } from '../palette.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, runDdItem, RW } from '../tw.ts'
import { FindingInspector } from './findings-inspector.tsx'

type Group = 'severity' | 'fix' | 'category' | 'origin' | 'status' | 'none'
type Sort = 'severity' | 'status' | 'title'
type Tab = 'all' | FindingTriageBucket
type Density = 'comfortable' | 'compact'
const GROUPS: [Group, string][] = [['severity', 'Severity'], ['fix', 'Fix status'], ['category', 'Category'], ['origin', 'Origin'], ['status', 'Status'], ['none', 'None']]
const SORTS: [Sort, string][] = [['severity', 'Severity'], ['status', 'Status'], ['title', 'Title']]
const TABS: [Tab, string][] = [['all', 'All'], ['confirmed', 'Confirmed'], ['static_verified', 'Static advisory'], ['needs_review', 'Needs review'], ['pending', 'Awaiting'], ['inconclusive', 'Inconclusive'], ['dismissed', 'Dismissed'], ['excluded', 'Out of scope'], ['suppressed', 'Suppressed']]
/** Tabs that live in the quiet low-priority fold unless they are the current tab. */
const LOW_PRIORITY: ReadonlySet<Tab> = new Set<Tab>(['excluded', 'suppressed'])
const TAB_LABEL = Object.fromEntries(TABS) as Record<Tab, string>
const BUCKET_ORDER = Object.fromEntries([...ACTIVE_TRIAGE_BUCKETS, 'suppressed'].map((b, i) => [b, i])) as Record<FindingTriageBucket, number>
const FIX_ORDER: Record<FindingFixState, number> = { still_reproducible: 0, verifying: 1, verified_fixed: 2, none: 3 }
const BUCKET_GLYPH: Partial<Record<FindingTriageBucket, string>> = { excluded: 'not_applicable', suppressed: 'stopped' }
const DENSITY: [Density, string][] = [['comfortable', 'Comfortable'], ['compact', 'Compact']]
/** Above this many rows the list is windowed (heads 32px, rows 36px comfortable / 30px compact). */
const VIRTUAL_AT = 300
const HEAD_H = 32
const ROW_HEIGHT: Record<Density, number> = { comfortable: 36, compact: 30 }

type Row = TriagedFindingRow<FindingRow> & { fix: FindingFixState }
interface G { key: string; label: string; glyph: ReactNode; items: Row[] }

export type FindingWithTriage = FindingRow & { operatorTriage?: OperatorTriage | null }

export interface TriageStatusOption {
  value: OperatorTriageStatus
  label: string
  short: string
  tone?: 'accent' | 'warn' | 'solid'
}

export function getTriageStatusOptions(): readonly TriageStatusOption[] {
  return [
    { value: 'open', label: 'Open', short: 'Open' },
    { value: 'accepted_risk', label: 'Accepted risk', short: 'Accepted risk', tone: 'solid' },
    { value: 'false_positive', label: 'False positive', short: 'False positive', tone: 'warn' },
    { value: 'fixed', label: 'Fixed', short: 'Fixed', tone: 'solid' },
    { value: 'confirmed_by_operator', label: 'Confirmed by operator', short: 'Confirmed (op)', tone: 'accent' },
  ]
}

export function getTriageStatusMeta(status: OperatorTriageStatus | string | undefined): TriageStatusOption {
  const options = getTriageStatusOptions()
  return options.find(o => o.value === status) ?? options[0]!
}

function matches(f: FindingRow, q: string) {
  if (!q) return true
  const triage = (f as FindingWithTriage).operatorTriage
  const triageMeta = triage ? getTriageStatusMeta(triage.status) : null
  const text = [
    f.title, f.origin, f.category, f.cwe, f.status, f.severity, f.id,
    triage?.status, triageMeta?.label, triage?.severityOverride, triage?.notes,
  ].join(' ').toLowerCase()
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(t => text.includes(t))
}

const bucketGlyph = (b: FindingTriageBucket) => <StatusGlyph status={BUCKET_GLYPH[b] ?? b} />

/** Group key/label/glyph per grouping; the Suppressed tab always groups by suppression reason. */
function groupKey(r: Row, g: Group, suppressedTab: boolean): [string, string, ReactNode, number | string] {
  if (suppressedTab) {
    const by = r.item.suppressedBy ?? 'false_positive'
    return [by, by === 'accepted_risk' ? 'Accepted risk' : 'False positive', bucketGlyph('suppressed'), by]
  }
  switch (g) {
    case 'severity': return [r.effectiveSeverity, SEV_LABEL[r.effectiveSeverity] ?? r.effectiveSeverity, <SevGlyph sev={r.effectiveSeverity} />, SEV_ORDER[r.effectiveSeverity] ?? 9]
    case 'fix': return [r.fix, FIX_STATE_LABEL[r.fix], <StatusGlyph status={r.fix === 'verified_fixed' ? 'fixed' : r.fix === 'still_reproducible' ? 'failed' : r.fix === 'verifying' ? 'running' : 'pending'} />, FIX_ORDER[r.fix]]
    case 'category': { const c = prettyCat(r.finding.category); return [c, c, <span className="inline-flex text-fg-subtle"><Icon name="grid" /></span>, c] }
    case 'status': return [r.bucket, TAB_LABEL[r.bucket], bucketGlyph(r.bucket), BUCKET_ORDER[r.bucket]]
    default: { const h = host(r.finding.origin) || '—'; return [h, h, <span className="inline-flex text-fg-subtle"><Icon name="globe" /></span>, h] }
  }
}

function groupOf(items: Row[], g: Group, suppressedTab: boolean): G[] | null {
  if (g === 'none' && !suppressedTab) return null
  const m = new Map<string, { label: string; glyph: ReactNode; order: number | string; items: Row[] }>()
  for (const r of items) {
    const [k, label, glyph, order] = groupKey(r, g, suppressedTab)
    const e = m.get(k)
    if (e) e.items.push(r)
    else m.set(k, { label, glyph, order, items: [r] })
  }
  return [...m.entries()]
    .sort((a, b) => (typeof a[1].order === 'number' && typeof b[1].order === 'number' ? a[1].order - b[1].order : String(a[1].order).localeCompare(String(b[1].order))))
    .map(([key, e]) => ({ key, label: e.label, glyph: e.glyph, items: e.items }))
}

// ---------------------------------------------------------------- verdict strip

function VerdictStrip() {
  const model = useRunModel()
  const v = useVerdict()
  const nav = useNav()
  const [open, setOpen] = useViewState('findings.vstrip', true)
  if (model.run.status === 'waiting') return null
  return <div
    className={cn(
      'flex min-w-0 flex-none cursor-pointer select-none items-center gap-2.5 border-b border-line pl-[18px] pr-3 text-[12.5px] text-fg-muted hover:text-fg',
      open ? 'h-9 bg-sunk' : 'h-7 bg-transparent',
    )}
    role="button"
    tabIndex={0}
    aria-expanded={open}
    title={(open ? 'Collapse' : 'Expand') + ' the run summary'}
    onClick={() => setOpen(!open)}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(!open) } }}
  >
    <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', !open && '-rotate-90')} />
    {open ? <>
      <span className="min-w-0 flex-1 truncate font-medium text-fg">{v.hed}</span>
      <span className="inline-flex flex-none items-center gap-1.5 text-fg-subtle">{v.conf.word === 'Not yet assessed' ? v.conf.word : v.conf.word + ' confidence'}</span>
    </> : <span className="flex-1 text-[12px] text-fg-subtle">Run summary</span>}
    <button
      type="button"
      className={runBtn({ variant: 'link', size: 'none' })}
      onClick={e => { e.stopPropagation(); nav.setView('overview') }}
    >
      Overview<Icon name="arrowR" />
    </button>
  </div>
}

// ---------------------------------------------------------------- toolbar

/** Quiet fold for low-priority tabs (Out of scope, Suppressed); hidden when empty. */
function LowPriorityFold({ tabs, onPick }: { tabs: [Tab, string, number][]; onPick: (t: Tab) => void }) {
  if (!tabs.length) return null
  return <Dropdown
    className="flex-none"
    btnClassName="inline-flex h-[26px] flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 bg-transparent px-[9px] text-[12.5px] font-normal tabular-nums text-fg-subtle shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg"
    title={'Low priority: ' + tabs.map(t => `${t[1]} ${t[2]}`).join(' · ')}
    label={<span data-slot="low-priority-fold" className="inline-flex items-center gap-1"><Icon name="archive" /><span className="sr-only">Low priority</span>{tabs.reduce((n, t) => n + t[2], 0)}</span>}
    menuClassName="top-[30px] w-[200px] p-1.5"
    align="left"
  >
    {close => tabs.map(([k, l, n]) => <button key={k} type="button" role="menuitem" data-tab={k} className={runDdItem()} onClick={() => { onPick(k); close() }}>
      {l}<span className="num ml-auto text-fg-subtle">{n}</span>
    </button>)}
  </Dropdown>
}

function Toolbar({ tabs, folded, tab, setTab, filter, setFilter, filterRef, onFilterEnter, group, setGroup, sort, setSort, density, setDensity }: {
  tabs: [Tab, string, number][]
  folded: [Tab, string, number][]
  tab: Tab
  setTab: (t: Tab) => void
  filter: string
  setFilter: (s: string) => void
  filterRef: RefObject<HTMLInputElement | null>
  onFilterEnter: () => void
  group: Group
  setGroup: (g: Group) => void
  sort: Sort
  setSort: (s: Sort) => void
  density: Density
  setDensity: (d: Density) => void
}) {
  return <div className={RW.toolbar}>
    <Tabs tabs={tabs} value={tab} onChange={setTab} label="Filter findings by status" />
    <LowPriorityFold tabs={folded} onPick={setTab} />
    <FilterBox ref={filterRef} value={filter} onChange={setFilter} onEnter={onFilterEnter} label="Filter findings" />
    <Dropdown icon="sliders" title="Display options (⇧G cycles grouping)"
      label={<><span className="text-fg-subtle">Group</span><span>{GROUPS.find(g => g[0] === group)?.[1]}</span></>}>
      <div className={RW.ddSec}>Grouping<KbdGroup keys={['⇧', 'G']} className="ml-auto" /></div>
      <Seg<Group> value={group} onChange={setGroup} options={GROUPS.slice(0, 3).map(([value, label]) => ({ value, label }))} fullWidth />
      <Seg<Group> value={group} onChange={setGroup} options={GROUPS.slice(3).map(([value, label]) => ({ value, label }))} fullWidth className="mt-1" />
      <div className={RW.ddSec}>Ordering</div>
      <Seg<Sort> value={sort} onChange={setSort} options={SORTS.map(([value, label]) => ({ value, label }))} fullWidth />
      <div className={RW.ddSec}>Density</div>
      <Seg<Density> value={density} onChange={setDensity} options={DENSITY.map(([value, label]) => ({ value, label }))} fullWidth label="Row density" />
    </Dropdown>
  </div>
}

// ---------------------------------------------------------------- rows

/** True when FindingTriageBadges renders anything (status ≠ open, severity override, or notes). */
function hasTriageBadges(triage: OperatorTriage | null | undefined): boolean {
  return Boolean(triage && (triage.status !== 'open' || triage.severityOverride || triage.notes?.trim()))
}

function FindingTriageBadges({ triage }: { triage: OperatorTriage | null | undefined }) {
  if (!triage || !hasTriageBadges(triage)) return null
  const hasStatus = triage.status !== 'open'
  const hasOverride = Boolean(triage.severityOverride)
  const hasNotes = Boolean(triage.notes?.trim())
  const meta = getTriageStatusMeta(triage.status)
  return <span className="flex flex-none items-center gap-1" data-slot="finding-triage-badges">
    {hasStatus && <Tag tone={meta.tone} title={triage.notes || meta.label}>{meta.short}</Tag>}
    {hasOverride && <Tag title={`Operator severity override: ${SEV_LABEL[triage.severityOverride!] ?? triage.severityOverride}`}>{SEV_LABEL[triage.severityOverride!] ?? triage.severityOverride} (op)</Tag>}
    {!hasStatus && !hasOverride && hasNotes && <Tag tone="solid" title={triage.notes}>Note</Tag>}
  </span>
}

function FindingRowView({ r, group, showFix, density, cur, onClick, style }: {
  r: Row
  group: Group
  showFix: boolean
  density: Density
  cur: boolean
  onClick: () => void
  style?: CSSProperties
}) {
  const f = r.finding
  const triage = (f as FindingWithTriage).operatorTriage
  const badges = hasTriageBadges(triage)
  const machine = r.severityOverridden ? `Severity overridden to ${SEV_LABEL[r.effectiveSeverity]}; machine severity ${SEV_LABEL[r.machineSeverity]}` : undefined
  return <div
    className={cn(RW.row, 'cursor-pointer', density === 'compact' && 'h-[30px] [contain-intrinsic-size:auto_30px]', cur && RW.rowCur)}
    data-id={f.id}
    data-bucket={r.bucket}
    onClick={onClick}
    style={style}
    title={machine}
    aria-selected={cur}
  >
    <SevCell sev={r.effectiveSeverity} machine={r.severityOverridden ? r.machineSeverity : null} />
    <span className="inline-flex size-3.5 flex-none items-center justify-center" title={TAB_LABEL[r.bucket]}>{bucketGlyph(r.bucket)}</span>
    <span data-slot="finding-title" className="min-w-[38%] flex-1 truncate text-fg" title={f.title || undefined}>
      <FindingTitle title={f.title} />
    </span>
    {r.bucket === 'needs_review' && <Tag tone="warn" className="flex-none">Needs review</Tag>}
    <FindingTriageBadges triage={triage} />
    {showFix && <span className="flex w-[124px] flex-none"><FixStatePill state={r.fix} /></span>}
    {f.category && group !== 'category' && <span className={cn('min-w-0 max-w-[155px] shrink truncate text-[12px] text-fg-subtle max-[1360px]:hidden', (badges || showFix) && 'max-[1440px]:hidden')} title={prettyCat(f.category)}>{prettyCat(f.category)}</span>}
    {group !== 'origin' && <span className="w-[150px] min-w-0 shrink truncate text-right font-mono text-[12px] text-fg-subtle max-[1320px]:w-[120px] max-[1180px]:hidden" title={host(f.origin) || undefined}>{host(f.origin)}</span>}
  </div>
}

function GroupHead({ g, group, collapsed, onToggle, style, className }: {
  g: G
  group: Group
  collapsed: boolean
  onToggle: () => void
  style?: CSSProperties
  className?: string
}) {
  const t: Partial<Record<FindingTriageBucket, number>> = {}
  for (const r of g.items) t[r.bucket] = (t[r.bucket] ?? 0) + 1
  return <div
    className={cn(RW.ghead, className)}
    role="button"
    tabIndex={0}
    aria-expanded={!collapsed}
    data-group={g.key}
    style={style}
    onClick={onToggle}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}
  >
    <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', collapsed && '-rotate-90')} />
    <span className="inline-flex size-3.5 flex-none items-center justify-center">{g.glyph}</span>
    <span>{g.label}</span>
    <span className="font-normal tabular-nums text-fg-subtle" data-slot="group-count">{g.items.length}</span>
    {group !== 'status' && <span className="ml-auto flex items-center gap-2 font-normal tabular-nums text-fg-subtle">
      {[...ACTIVE_TRIAGE_BUCKETS, 'suppressed' as const].filter(k => t[k]).map(k => <span key={k} className="inline-flex items-center gap-[5px]" title={TAB_LABEL[k]}>{bucketGlyph(k)}{t[k]}</span>)}
    </span>}
  </div>
}

// ---------------------------------------------------------------- view

/** The single triage-aware projection for this run (same scope context as the headline verdict) + fix states. */
function useFindingRows() {
  const model = useRunModel()
  return useMemo(() => {
    const p = projectTriagedFindings(model.findings, runFindingsScopeContext(model.run, model.detail.facts))
    const fix = indexFindingFixStates(p.rows.map(r => r.finding), model.detail)
    const rows: Row[] = p.rows.map(r => ({ ...r, fix: fix.get(r.finding.id)?.state ?? 'none' }))
    return { rows, counts: p.counts, showFix: rows.some(r => r.fix !== 'none') }
  }, [model])
}

/** Tabs with items: primary tabs inline, low-priority ones folded unless current. */
function useTabs(counts: ReturnType<typeof useFindingRows>['counts'], tab: Tab) {
  return useMemo(() => {
    const withN = TABS.filter(([k]) => counts[k] > 0).map(([k, l]) => [k, l, counts[k]] as [Tab, string, number])
    return {
      inline: withN.filter(t => !LOW_PRIORITY.has(t[0]) || t[0] === tab),
      folded: withN.filter(t => LOW_PRIORITY.has(t[0]) && t[0] !== tab),
      has: (t: Tab) => withN.some(x => x[0] === t),
    }
  }, [counts, tab])
}

export function FindingsView() {
  const model = useRunModel()
  const nav = useNav()
  const toast = useToast()
  const [tab, setTab] = useViewState<Tab>('findings.tab', 'all')
  const [filter, setFilter] = useViewState('findings.filter', '')
  const [group, setGroup] = useViewState<Group>('findings.group', 'severity')
  const [sort, setSort] = useViewState<Sort>('findings.sort', 'severity')
  const [density, setDensity] = useViewState<Density>('findings.density', 'comfortable')
  const [collapsed, setCollapsed] = useViewState<Record<string, boolean>>('findings.collapsed', {})
  const filterRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const ROW_H = ROW_HEIGHT[density]

  const projected = useFindingRows()
  const tabSet = useTabs(projected.counts, tab)
  const activeTab: Tab = tabSet.has(tab) ? tab : 'all'
  const suppressedTab = activeTab === 'suppressed'

  const items = useMemo(() => {
    const list = projected.rows.filter(r => (activeTab === 'all' ? r.bucket !== 'suppressed' : r.bucket === activeTab) && matches(r.finding, filter))
    const sev = (a: Row, b: Row) => (SEV_ORDER[a.effectiveSeverity] ?? 9) - (SEV_ORDER[b.effectiveSeverity] ?? 9)
    const st = (a: Row, b: Row) => BUCKET_ORDER[a.bucket] - BUCKET_ORDER[b.bucket]
    const ti = (a: Row, b: Row) => a.finding.title.localeCompare(b.finding.title)
    return list.sort((a, b) => sort === 'title' ? ti(a, b)
      : sort === 'status' ? st(a, b) || sev(a, b) || ti(a, b)
        : sev(a, b) || st(a, b) || ti(a, b))
  }, [projected, activeTab, filter, sort])
  const groups = useMemo(() => groupOf(items, group, suppressedTab), [items, group, suppressedTab])
  const gk = suppressedTab ? 'suppressed' : group
  const ck = (g: G) => gk + ':' + g.key
  const flatIds = useMemo(() => groups ? groups.flatMap(g => (collapsed[gk + ':' + g.key] ? [] : g.items.map(r => r.finding.id))) : items.map(r => r.finding.id),
    [groups, items, collapsed, gk])

  const { index } = useListNav({ ids: flatIds, kind: 'finding' })
  const cycleGroup = () => {
    const i = GROUPS.findIndex(g => g[0] === group)
    const next = GROUPS[(i + 1) % GROUPS.length]
    setGroup(next[0])
    toast.show(next[0] === 'none' ? 'Ungrouped' : 'Grouped by ' + next[1].toLowerCase())
  }
  useShortcuts([{ key: 'G', run: cycleGroup }])
  usePaletteCommands([
    ...GROUPS.map(([k, l]) => ({ id: 'f.group.' + k, section: 'Actions', label: k === 'none' ? 'Findings: no grouping' : 'Findings: group by ' + l.toLowerCase(), icon: 'sliders' as const, run: () => setGroup(k) })),
    { id: 'f.density', section: 'Actions', label: density === 'compact' ? 'Findings: comfortable rows' : 'Findings: compact rows', icon: 'list', run: () => setDensity(density === 'compact' ? 'comfortable' : 'compact') },
    { id: 'f.filter', section: 'Actions', label: 'Filter findings', icon: 'search', keys: ['/'], run: () => setTimeout(() => filterRef.current?.focus(), 0) },
  ])

  const selId = nav.sel?.kind === 'finding' ? nav.sel.id : null
  const select = (id: string) => nav.select({ kind: 'finding', id })

  // Windowed rendering for long lists.
  const flatEntries = useMemo(() => {
    const out: ({ t: 'h'; g: G } | { t: 'r'; r: Row })[] = []
    if (groups) for (const g of groups) { out.push({ t: 'h', g }); if (!collapsed[ck(g)]) g.items.forEach(r => out.push({ t: 'r', r })) }
    else items.forEach(r => out.push({ t: 'r', r }))
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, items, collapsed, gk])
  const virtualAt = useVirtualThreshold()
  const virtual = items.length > virtualAt
  const offsets = useMemo(() => {
    const o: number[] = []
    let y = 0
    for (const e of flatEntries) { o.push(y); y += e.t === 'h' ? HEAD_H : ROW_H }
    o.push(y)
    return o
  }, [flatEntries, ROW_H])
  const [win, setWin] = useState<[number, number]>([0, 80])
  useLayoutEffect(() => {
    const el = listRef.current
    if (!el || !virtual) return
    const update = () => {
      const top = el.scrollTop
      const bottom = top + el.clientHeight
      let lo = 0, hi = flatEntries.length
      while (lo < hi) { const mid = (lo + hi) >> 1; if (offsets[mid + 1] <= top) lo = mid + 1; else hi = mid }
      let end = lo
      while (end < flatEntries.length && offsets[end] < bottom) end++
      const a = Math.max(0, lo - 10), b = Math.min(flatEntries.length, end + 10)
      setWin(w => (w[0] === a && w[1] === b ? w : [a, b]))
    }
    update()
    el.addEventListener('scroll', update, { passive: true })
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => { el.removeEventListener('scroll', update); ro.disconnect() }
  }, [virtual, flatEntries, offsets])

  // Keep the cursor row in view.
  useEffect(() => {
    if (!selId) return
    const el = listRef.current
    if (!el) return
    if (virtual) {
      const i = flatEntries.findIndex(e => e.t === 'r' && e.r.finding.id === selId)
      if (i < 0) return
      const top = offsets[i]
      const head = groups ? HEAD_H : 0
      if (top - head < el.scrollTop) el.scrollTop = top - head
      else if (top + ROW_H > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW_H - el.clientHeight
      return
    }
    el.querySelector<HTMLElement>(`[data-id="${CSS.escape(selId)}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [selId, index, virtual, flatEntries, offsets, groups, ROW_H])

  const toggle = (g: G) => setCollapsed(c => ({ ...c, [ck(g)]: !c[ck(g)] }))
  const toolbar = <Toolbar tabs={tabSet.inline} folded={tabSet.folded} tab={activeTab} setTab={setTab} filter={filter} setFilter={setFilter} filterRef={filterRef}
    onFilterEnter={() => { if (flatIds[0]) { select(flatIds[0]); filterRef.current?.blur() } }}
    group={group} setGroup={setGroup} sort={sort} setSort={setSort} density={density} setDensity={setDensity} />
  const rowProps = { group: suppressedTab ? 'none' as const : group, showFix: projected.showFix, density }

  if (!model.findings.length) {
    // No filter / display controls: there is nothing to filter or group yet.
    return <>
      <VerdictStrip />
      <FindingsEmpty />
    </>
  }

  let body: ReactNode
  if (!items.length) {
    body = <EmptyState icon="search" title="Nothing matches"
      action={<button type="button" className={runBtn()} onClick={() => { setFilter(''); setTab('all') }}>Clear filter</button>}>
      Try a different filter or switch tabs.
    </EmptyState>
  } else if (virtual) {
    // current group head pinned at the top while scrolling (heads in the window scroll normally)
    let pinned: G | null = null
    if (groups) for (let i = win[0]; i >= 0; i--) { const e = flatEntries[i]; if (e?.t === 'h') { pinned = e.g; break } }
    body = <>
      {pinned && <div className="sticky top-0 z-[3] h-0"><GroupHead g={pinned} group={group} collapsed={!!collapsed[ck(pinned)]} onToggle={() => toggle(pinned!)} className="relative" /></div>}
      <div className="relative w-full" style={{ height: offsets[offsets.length - 1] }}>
        {flatEntries.slice(win[0], win[1]).map((e, j) => {
          const i = win[0] + j
          const style: CSSProperties = { position: 'absolute', top: offsets[i], left: 0, right: 0, height: e.t === 'h' ? HEAD_H : ROW_H }
          return e.t === 'h'
            ? <GroupHead key={'h:' + e.g.key} g={e.g} group={group} collapsed={!!collapsed[ck(e.g)]} onToggle={() => toggle(e.g)} className="absolute" style={style} />
            : <FindingRowView key={e.r.finding.id} r={e.r} {...rowProps} cur={e.r.finding.id === selId} onClick={() => select(e.r.finding.id)} style={style} />
        })}
      </div>
    </>
  } else {
    body = groups
      ? groups.map(g => <div key={g.key} className="relative">
        <GroupHead g={g} group={group} collapsed={!!collapsed[ck(g)]} onToggle={() => toggle(g)} />
        {!collapsed[ck(g)] && g.items.map(r => <FindingRowView key={r.finding.id} r={r} {...rowProps} cur={r.finding.id === selId} onClick={() => select(r.finding.id)} />)}
      </div>)
      : items.map(r => <FindingRowView key={r.finding.id} r={r} {...rowProps} cur={r.finding.id === selId} onClick={() => select(r.finding.id)} />)
  }
  return <>
    <VerdictStrip />
    {toolbar}
    <div className={RW.list} ref={listRef} tabIndex={-1} data-density={density}>{body}</div>
  </>
}

/** Zero-findings empty state, worded by run state (finished, paused, waiting, in progress). */
function FindingsEmpty() {
  const model = useRunModel()
  const { send, pending } = useRun()
  const nav = useNav()
  const toast = useToast()
  const run = model.run
  if (run.status === 'complete') {
    return <EmptyState icon="findings" title="No weaknesses confirmed"
      action={<button type="button" className={runBtn()} onClick={() => nav.setView('report')}><Icon name="report" />Open report</button>}>
      Every proposed finding was ruled out by replay.
    </EmptyState>
  }
  if (canOfferResumeButton(run)) {
    const resume = () => send({ action: 'resume' }).then(() => toast.show('Resuming the run'), () => {})
    return <EmptyState icon="findings" title="Paused before any findings"
      action={<button type="button" className={runBtn()} disabled={pending > 0} onClick={() => void resume()}><Icon name="play" />Resume</button>}>
      Resume the run to let workers continue proposing findings.
    </EmptyState>
  }
  return <EmptyState icon="findings" title="No findings yet"
    action={run.status === 'waiting' ? <button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
    Findings appear here as workers propose them; each one is verified by automated replay before it is marked confirmed.
  </EmptyState>
}

/** Rows above which the list is windowed. `localStorage['kovo-rw-virtual-at']` overrides it (testing). */
function useVirtualThreshold() {
  const [n, setN] = useState(VIRTUAL_AT)
  useEffect(() => {
    const v = Number(localStorage.getItem('kovo-rw-virtual-at'))
    if (v > 0) setN(v)
  }, [])
  return n
}

/** Inspectors this view owns, keyed by selection kind ('finding'). */
export const findingsInspectors: InspectorMap = {
  finding: FindingInspector,
}
