// Workflow graph canvas (Agent W): HTML cards + one SVG edge layer inside a
// transform-panned canvas. The camera, minimap, tooltip and replay frames are
// driven imperatively (refs + rAF) so panning, zooming and replay never
// re-render React; React renders only when the layout, focus or filter change.
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, PointerEvent as RPointerEvent } from 'react'
import { useRun } from '../data.tsx'
import { clamp, deriveRound0PipelineState, fmtDate, fmtN, fmtRel, firstSentence, host, isRound0ThreatModelWorker, plural } from '../format.ts'
import { LiveDot, LiveGlyph, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { PHASE_LABEL, stLabel } from '../meta.ts'
import { aggStatus, worstSeverity } from '../model.ts'
import type { FindingRow, RunEvent, RunModel } from '../model.ts'
import { DUR, EASE_CSS, ease, reducedMotion, T } from '../motion.tsx'
import { useTheme } from '../theme.ts'
import { cn, runIconBtn } from '../tw.ts'
import { allNodes, bounds, edgePath, hotEdges, isLive, nodeLineage, onCameraRequest, replaySpans, WF } from './workflow-layout.ts'
import type { WfEdge, WfHead, WfLayout, WfNode } from './workflow-layout.ts'

interface Cam { x: number; y: number; k: number }
/** Camera per run, kept across view switches. */
const camStore = new Map<string, Cam>()
/** User-toggled phase collapse overrides per run (phase → collapsed), kept across view switches. */
const phaseOverrideStore = new Map<string, Map<string, boolean>>()

/** Below this zoom the cards switch to semantic-zoom compact cards (glyph + large title). */
export const SEMANTIC_LOD_K = 0.80
/** The initial and follow-live cameras never frame work below this zoom. */
export const LEGIBILITY_FLOOR_K = 0.85
/** Width of a collapsed completed-phase summary lane, and the gap after it. */
export const COLLAPSED_PHASE_W = 196
export const COLLAPSED_PHASE_GAP = 48
/** The minimap appears only when the scaled graph exceeds this multiple of the viewport. */
export const MINIMAP_OVERFLOW_RATIO = 2

/** A finished worker phase that is neither live nor the run's current phase. */
export function isCompletedPhaseHead(head: WfHead, runPhase: string): boolean {
  return head.phase !== 'report' && !head.live && head.phase !== runPhase && head.n > 0 && head.done >= head.n
}

/**
 * Phases folded to summary lanes by default: every completed phase while work is still active;
 * on a finished run, every completed phase but the last so the final work column stays open.
 */
export function defaultCollapsedPhases(heads: readonly WfHead[], runPhase: string): Set<string> {
  const done = heads.filter(h => isCompletedPhaseHead(h, runPhase))
  const active = heads.some(h => h.phase !== 'report' && !isCompletedPhaseHead(h, runPhase) && (h.live || h.phase === runPhase || (h.n > 0 && h.done < h.n)))
  if (active) return new Set(done.map(h => h.phase))
  if (done.length < 2) return new Set()
  return new Set(done.slice(0, -1).map(h => h.phase))
}

export interface CollapsedHead { head: WfHead; x: number; w: number; workerCount: number; findingsCount?: number }

/**
 * Re-pack the phase columns with collapsed phases folded into narrow summary lanes (their nodes and
 * edges hidden). Visible cards are lifted together when the rows above them belonged to folded phases.
 */
export function projectWorkflowLayout(L: WfLayout, collapsedPhases: ReadonlySet<string>): { layout: WfLayout; collapsedHeads: CollapsedHead[] } {
  if (!collapsedPhases.size) return { layout: L, collapsedHeads: [] }
  const heads: WfHead[] = []
  const collapsedHeads: CollapsedHead[] = []
  const dxByPhase = new Map<string, number>()
  let x = 0
  for (const h of L.heads) {
    if (h.phase !== 'report' && collapsedPhases.has(h.phase)) {
      heads.push({ ...h, x, w: COLLAPSED_PHASE_W })
      collapsedHeads.push({ head: h, x, w: COLLAPSED_PHASE_W, workerCount: h.n + h.earlier })
      x += COLLAPSED_PHASE_W + COLLAPSED_PHASE_GAP
      continue
    }
    dxByPhase.set(h.phase, x - h.x)
    heads.push(x === h.x ? h : { ...h, x })
    x += h.w + WF.PG
  }
  const kept = L.nodes.filter(n => dxByPhase.has(n.phase))
  const dy = Math.max(0, Math.min(...kept.map(n => n.y), L.report?.y ?? Infinity) - WF.HH)
  const shift = (n: WfNode): WfNode => {
    const dx = dxByPhase.get(n.phase) ?? 0
    return dx || dy ? { ...n, x: n.x + dx, y: n.y - dy } : n
  }
  const nodes = kept.map(shift)
  const report = L.report ? shift(L.report) : null
  const byId = new Map<string, WfNode>(nodes.map(n => [n.id, n]))
  if (report) byId.set(report.id, report)
  const edges = L.edges.filter(e => byId.has(e.from) && byId.has(e.to))
  const inc = new Map<string, string[]>()
  const out = new Map<string, string[]>()
  for (const e of edges) {
    inc.set(e.to, [...(inc.get(e.to) ?? []), e.from])
    out.set(e.from, [...(out.get(e.from) ?? []), e.to])
  }
  const W = Math.max(WF.NW, ...heads.map(h => h.x + h.w))
  const H = Math.max(WF.HH + WF.NH, ...nodes.map(n => n.y + WF.NH), report ? report.y + WF.NH : 0)
  return { layout: { ...L, nodes, byId, edges, inc, out, heads, W, H, report }, collapsedHeads }
}

/** Semantic zoom tier for a camera zoom. */
export function semanticZoomTier(k: number): 'compact' | 'full' {
  return k < SEMANTIC_LOD_K ? 'compact' : 'full'
}

/** The minimap only earns its corner when the scaled graph is far larger than the viewport. */
export function shouldShowMinimap(contentW: number, contentH: number, viewportW: number, viewportH: number, k: number): boolean {
  return viewportW > 0 && viewportH > 0 && (contentW * k > viewportW * MINIMAP_OVERFLOW_RATIO || contentH * k > viewportH * MINIMAP_OVERFLOW_RATIO)
}

const liveRank = (status: string) => status === 'running' ? 2 : status === 'paused' || status === 'waiting_approval' ? 1 : 0

/** Where the follow-live camera looks: the newest running (else paused) worker or stack, else the live phase. */
export function selectFollowLiveTarget(L: WfLayout): { node: WfNode | null; head: WfHead | null } {
  let node: WfNode | null = null, rank = 0, at = -Infinity
  for (const n of L.nodes) {
    const ms = n.kind === 'worker' ? [n.a!] : n.kind === 'stack' ? n.members ?? [] : []
    for (const a of ms) {
      const r = liveRank(a.status)
      if (r && (r > rank || (r === rank && a.createdAt > at))) { node = n; rank = r; at = a.createdAt }
    }
  }
  const head = (node ? L.heads.find(h => h.phase === node.phase) : undefined) ?? L.heads.find(h => h.live) ?? null
  return { node, head }
}

export interface GraphProps {
  L: WfLayout
  /** Selected node id (a worker, stack or the queued-steps card), already resolved to the layout. */
  selId: string | null
  /** Explicit highlight set (a graph digest's covered workers); overrides lineage. */
  focusSet: Set<string> | null
  nomatch: Set<string>
  onSelect: (id: string | null) => void
  onExpand: (gid: string, on: boolean) => void
  onReport: () => void
  replay: boolean
  onReplayClose: () => void
  /** Opened from the keyboard (L / palette): render settled, no entrance (A-137). */
  skipEntrance?: boolean
}

interface NodeInfo {
  facts: number
  findings: FindingRow[]
  idLabel: string
  host: string
  status: string
  reqs: number
  hosts: number
  hist?: string
  round0?: {
    stageShort: string
    mappedHosts: number
    totalHosts: number
    reqs: number
    live: boolean
  }
}

const titleOf = (n: WfNode) => n.kind === 'worker' ? n.a!.title : n.kind === 'stack' ? n.g!.title : n.kind === 'queue' ? 'Queued chain steps' : 'Report'

function nodeInfo(m: RunModel, L: WfLayout, events: readonly RunEvent[]): Map<string, NodeInfo> {
  const out = new Map<string, NodeInfo>()
  for (const n of L.nodes) {
    if (n.kind === 'worker') {
      const a = n.a!
      const step = a.stepId ? m.stepById.get(a.stepId) : m.stepByWorker.get(a.id)
      const round0State = isRound0ThreatModelWorker(a)
        ? deriveRound0PipelineState({ assignment: a, detail: m.detail, events })
        : null
      out.set(n.id, {
        facts: (m.factsByWorker.get(a.id) ?? []).filter(f => !f.tainted).length,
        findings: m.workerFindings.get(a.id) ?? [],
        idLabel: step ? '#' + step.seq + ' · P' + step.priority : PHASE_LABEL[a.phase] ?? a.phase,
        host: round0State && round0State.counts.totalHosts > 1
          ? plural(round0State.counts.totalHosts, 'host')
          : host(a.sourceOrigins[0] ?? ''),
        status: a.status,
        reqs: round0State ? round0State.counts.requests : a.requestsUsed,
        hosts: round0State ? round0State.counts.totalHosts : 1,
        hist: L.history.get(a.id),
        ...(round0State ? {
          round0: {
            stageShort: round0State.stageShort,
            mappedHosts: round0State.counts.mappedHosts,
            totalHosts: round0State.counts.totalHosts,
            reqs: round0State.counts.requests,
            live: isLive(a),
          },
        } : {}),
      })
    } else if (n.kind === 'stack') {
      const ms = n.members!
      const seen = new Set<string>()
      const findings = ms.flatMap(a => m.workerFindings.get(a.id) ?? []).filter(f => !seen.has(f.id) && !!seen.add(f.id))
      out.set(n.id, {
        facts: ms.reduce((s, a) => s + (m.factsByWorker.get(a.id) ?? []).filter(f => !f.tainted).length, 0),
        findings, idLabel: ms.length + ' workers', host: '', status: aggStatus(ms),
        reqs: ms.reduce((s, a) => s + a.requestsUsed, 0), hosts: new Set(ms.flatMap(a => a.sourceOrigins.slice(0, 1))).size,
      })
    } else if (n.kind === 'queue') {
      const st = n.steps!
      out.set(n.id, { facts: 0, findings: [], idLabel: plural(st.length, 'step'), host: '', status: 'queued', reqs: 0, hosts: 0 })
    }
  }
  return out
}

/**
 * Status glyph, or a live dot for running (accent) / paused (amber). Only the selected
 * node pulses; every other live node shows a static dot so the canvas carries one ping (A-130).
 */
/** Live glyph plus the replay variant (shown while the replay frontier passes the node). */
function Lv({ status, pulse }: { status: string; pulse?: boolean }) {
  return <span className="inline-flex size-3.5 flex-none items-center justify-center">
    <span className="contents group-data-[rp=live]/node:hidden"><LiveGlyph status={status} pulse={pulse} /></span>
    <span className="hidden group-data-[rp=live]/node:contents"><LiveDot /></span>
  </span>
}

function tickBgClass(status: string): string {
  switch (status) {
    case 'paused':
    case 'waiting_approval':
      return 'bg-warn'
    case 'failed':
      return 'bg-danger'
    case 'running':
      return 'bg-accent'
    case 'queued':
      return 'bg-line-strong'
    case 'ready':
      return 'bg-fg-subtle'
    case 'canceled':
      return 'bg-line-2'
    default:
      return 'bg-fg-faint'
  }
}

const NODE_BASE = 'group/node absolute flex h-[var(--nh)] w-[var(--nw)] cursor-pointer select-none flex-col gap-[3px] rounded-[9px] px-[11px] pb-2 pt-[9px] transition-[opacity,box-shadow,scale] duration-[var(--d2)] ease-kovo group-data-[lod]/wf:flex-row group-data-[lod]/wf:items-center group-data-[lod]/wf:gap-3 group-data-[lod]/wf:px-3.5 group-data-[lod]/wf:py-2.5 data-[rp=hidden]:pointer-events-none data-[rp=hidden]:scale-[.94] data-[rp=hidden]:opacity-0!'
const NODE_STACK_LAYERS = "before:content-[''] before:absolute before:inset-x-1.5 before:-bottom-[5px] before:-z-[1] before:h-2 before:rounded-b-[9px] before:bg-panel before:shadow-surface after:content-[''] after:absolute after:inset-x-3 after:-bottom-2.5 after:-z-[2] after:h-2 after:rounded-b-[9px] after:bg-panel after:opacity-70 after:shadow-surface"
const NODE_TOP = 'flex h-4 min-w-0 items-center gap-1.5 whitespace-nowrap text-[11.5px] tabular-nums group-data-[lod]/wf:hidden'
const NODE_TITLE = 'line-clamp-2 min-h-[34px] text-[12.5px] font-medium leading-[17px] group-data-[lod]/wf:min-h-0 group-data-[lod]/wf:min-w-0 group-data-[lod]/wf:flex-1 group-data-[lod]/wf:text-[18px] group-data-[lod]/wf:font-semibold group-data-[lod]/wf:leading-[22px]'
/** Status glyph shown beside the title only in the semantic-zoom compact tier. */
const NODE_LOD_GLYPH = 'hidden size-5 flex-none items-center justify-center [&>*]:scale-[1.45] group-data-[lod]/wf:inline-flex'
const NODE_BOT = 'mt-auto flex items-center gap-2 whitespace-nowrap text-[11px] tabular-nums group-data-[lod]/wf:hidden'
const NODE_BADGE_BASE = 'inline-flex h-[17px] items-center gap-1 rounded-[9px] px-1.5 text-[11px] font-medium shadow-[inset_0_0_0_1px_var(--line-2)]'
const NODE_BADGE = `${NODE_BADGE_BASE} bg-sunk text-fg-muted`
const NODE_BADGE_F = `${NODE_BADGE_BASE} bg-panel text-fg`
const NODE_HOVER = 'hover:shadow-[0_0_0_1px_var(--line-strong),0_4px_12px_-4px_rgba(0,0,0,.14)]'
const NODE_ICON = 'inline-flex size-3.5 flex-none items-center justify-center'
const REPORT_MUTE = 'text-[color-mix(in_srgb,var(--panel)_60%,transparent)]'

interface NodeFlags {
  sel: boolean
  hot: boolean
  nomatch: boolean
  member: boolean
  hist: boolean
}

const NodeCard = memo(function NodeCard({ n, info, flags, reportSub }: { n: WfNode; info?: NodeInfo; flags: NodeFlags; reportSub?: string }) {
  const style: CSSProperties = { left: n.x, top: n.y }
  const opacityCls = flags.hot ? 'opacity-100' : flags.nomatch ? 'opacity-25' : 'group-data-[focus]/wf:opacity-40'
  const status = info?.status ?? 'complete'
  const paused = status === 'paused' || status === 'waiting_approval'
  const shadowCls = flags.sel
    ? 'shadow-[0_0_0_1.5px_var(--accent),0_0_0_4px_var(--accent-soft),0_6px_16px_-6px_rgba(0,0,0,.18)]'
    : paused
      ? `shadow-[0_0_0_1px_var(--warn-line),var(--shadow-card)] ${NODE_HOVER}`
      : `shadow-surface ${NODE_HOVER}`

  if (n.kind === 'report') {
    return <div
      className={cn(NODE_BASE, 'border-0 bg-fg text-panel', shadowCls, opacityCls)}
      data-n="report"
      data-wf-kind="report"
      style={style}
      role="button"
      aria-label="Open the report"
    >
      <div className={cn(NODE_TOP, REPORT_MUTE)}>
        <span className={NODE_ICON}><Icon name="report" /></span>
        <span className="flex-none">Report</span>
        <span className="ml-auto min-w-0 truncate text-[11px]">{fmtDate(n.createdAt)}</span>
      </div>
      <span className={NODE_LOD_GLYPH}><Icon name="report" /></span>
      <div className={cn(NODE_TITLE, 'text-panel')}>{reportSub}</div>
      <div className={cn(NODE_BOT, REPORT_MUTE)}>
        <span>Open the report</span><span className="flex-1" /><Icon name="arrowR" />
      </div>
    </div>
  }
  const i = info!
  const nf = i.findings.length
  const badge = nf > 0 && <span className={NODE_BADGE_F}><SevGlyph sev={worstSeverity(i.findings)} />{nf}</span>
  const lodBadge = nf > 0 && <div className="absolute -right-[7px] -top-[7px] hidden gap-[3px] group-data-[lod]/wf:flex">
    <span className="flex h-[22px] min-w-[22px] items-center justify-center rounded-[11px] bg-fg px-1.5 text-[13px] font-semibold text-panel">{nf}</span>
  </div>

  if (n.kind === 'stack' || n.kind === 'queue') {
    const ticks = n.kind === 'stack' ? n.members!.slice(0, 40).map(a => a.status) : n.steps!.slice(0, 40).map(s => s.status === 'ready' ? 'ready' : 'queued')
    return <div
      className={cn(
        NODE_BASE,
        NODE_STACK_LAYERS,
        n.kind === 'queue' ? 'bg-[color-mix(in_srgb,var(--panel)_70%,var(--sunk))]' : 'bg-panel',
        shadowCls,
        opacityCls,
      )}
      data-n={n.id}
      data-wf-kind={n.kind}
      style={style}
      role="button"
      aria-label={titleOf(n)}
    >
      <div className={cn(NODE_TOP, 'text-fg-subtle')}>
        {n.kind === 'stack'
          ? <Lv status={i.status} pulse={flags.sel} />
          : <span className={cn(NODE_ICON, 'text-fg-subtle')}><Icon name="queue" /></span>}
        <span
          className="flex-none tabular-nums"
          data-wf-id=""
          data-def={n.kind === 'stack' ? i.idLabel + ' · ' + plural(i.hosts, 'host') : undefined}
        >
          {n.kind === 'stack' ? i.idLabel + ' · ' + plural(i.hosts, 'host') : i.idLabel + ' waiting'}
        </span>
        {n.kind === 'stack' && (
          <button
            type="button"
            className="ml-auto inline-flex h-[18px] flex-none cursor-pointer items-center rounded-[5px] border-0 bg-panel px-1.5 font-sans text-[11px] font-normal text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)] transition-[background-color,color] duration-[var(--d1)] hover:bg-sunk hover:text-fg"
            data-wfexpand={n.id}
            title="Expand the stack (double-click)"
          >
            Expand
          </button>
        )}
      </div>
      <span className={NODE_LOD_GLYPH}>{n.kind === 'stack' ? <Lv status={i.status} /> : <Icon name="queue" />}</span>
      <div className={cn(NODE_TITLE, n.kind === 'queue' ? 'text-fg-muted' : i.status === 'failed' ? 'text-danger' : 'text-fg')}>
        {n.kind === 'stack' ? n.g!.title : 'Queued chain steps'}
      </div>
      <div className={cn(NODE_BOT, 'text-fg-subtle')}>
        <span className="flex items-center gap-[1.5px]" data-wf-ticks="">
          {ticks.map((s, k) => <i key={k} className={cn('h-[9px] w-[3px] rounded-[1px] transition-opacity duration-[var(--d2)]', tickBgClass(s))} />)}
        </span>
        {n.kind === 'stack' ? <span>{fmtN(i.reqs)} req</span> : <span>Not yet dispatched</span>}
        <span className="flex-1" />
        {i.facts > 0 && <span className={NODE_BADGE}>{fmtN(i.facts)} facts</span>}
        {badge}
      </div>
      {lodBadge}
    </div>
  }
  const a = n.a!
  return <div
    className={cn(
      NODE_BASE,
      flags.member ? 'bg-[color-mix(in_srgb,var(--panel)_88%,var(--sunk))]' : 'bg-panel',
      flags.hist && '[background-image:repeating-linear-gradient(135deg,transparent_0_6px,color-mix(in_srgb,var(--fg)_3%,transparent)_6px_7px)]',
      shadowCls,
      opacityCls,
    )}
    data-n={n.id}
    data-wf-kind="worker"
    style={style}
    role="button"
    aria-label={a.title + ', ' + stLabel(a.status)}
  >
    <div className={cn(NODE_TOP, 'text-fg-subtle')}>
      <Lv status={a.status} pulse={flags.sel} />
      <span className="flex-none font-mono text-[11.5px]" data-wf-id="">{i.idLabel}</span>
      {i.hist
        ? <span className="ml-auto min-w-0 truncate font-sans text-[11px] text-warn">{i.hist}</span>
        : <span className="ml-auto min-w-0 truncate font-mono text-[11px]">{i.host}</span>}
    </div>
    <span className={NODE_LOD_GLYPH}><Lv status={a.status} pulse={flags.sel} /></span>
    <div className={cn(NODE_TITLE, a.status === 'failed' ? 'text-danger' : flags.hist ? 'text-fg-muted' : 'text-fg')}>
      {a.title}
    </div>
    <div className={cn(NODE_BOT, 'text-fg-subtle')}>
      {i.round0 ? <>
        <span
          data-wf-round0-stage=""
          className={cn(
            NODE_BADGE,
            i.round0.live && 'bg-accent-soft text-accent shadow-[inset_0_0_0_1px_var(--accent-line)]',
          )}
        >
          {i.round0.stageShort}
        </span>
        {i.round0.totalHosts > 0 && <span>{i.round0.mappedHosts}/{i.round0.totalHosts} hosts</span>}
        <span>{fmtN(i.round0.reqs)} req</span>
      </> : <>
        <span>{fmtN(a.turnsUsed)}/{fmtN(a.maxTurns)} turns</span>
        <span>{fmtN(a.requestsUsed)} req</span>
      </>}
      <span className="flex-1" />
      {!i.round0 && i.facts > 0 && <span className={NODE_BADGE}>{plural(i.facts, 'fact')}</span>}
      {badge}
    </div>
    {lodBadge}
  </div>
})

const Edge = memo(function Edge({ d, e, hot }: { d: string; e: WfEdge; hot: boolean }) {
  return <path
    className={cn(
      'fill-none transition-[opacity,stroke,stroke-width] duration-[var(--d2)] ease-kovo data-[rp=hidden]:hidden',
      e.kind === 'causal' && '[stroke-dasharray:4_3]',
      hot
        ? cn('opacity-100 stroke-accent', e.kind === 'causal' ? '[stroke-width:1.6]' : '[stroke-width:1.8]')
        : cn('[stroke-width:1.3] group-data-[focus]/wf:opacity-[.12]', e.kind === 'report' ? 'stroke-[var(--edge-2)]' : 'stroke-[var(--edge)]'),
    )}
    data-e={e.key}
    d={d}
    pathLength={e.kind !== 'causal' ? 1 : undefined}
    markerEnd={hot ? 'url(#rw-wf-ahh)' : 'url(#rw-wf-ah)'}
  />
})

/** Initial-fit insets: phase bar (top) and the minimap footprint (right / bottom) when it shows. */
const CAM_INSET = { top: 44, right: 224, bottom: 148 }

/**
 * Initial camera (A-136): show the whole graph when it fits at a legible zoom (≥ 0.85);
 * otherwise frame the live phase (or the largest open column, with the collapsed lanes just
 * before it when they fit) at 0.85–1×. The minimap inset applies only when the minimap shows.
 */
function initialCamera(Lc: WfLayout, W: number, H: number, collapsed: ReadonlySet<string> = new Set()): Cam {
  const b = bounds(Lc)
  const top = CAM_INSET.top
  const frame = (right: number, bottom: number): Cam => {
    const availW = Math.max(160, W - right)
    const availH = Math.max(120, H - top - bottom)
    const kAll = Math.min(availW / b.w, availH / b.h)
    if (kAll >= LEGIBILITY_FLOOR_K) {
      const k = Math.min(1, kAll)
      return { k, x: (availW - b.w * k) / 2 - b.x * k, y: top - b.y * k }
    }
    let head: WfHead | undefined = Lc.heads.find(h => h.live && !collapsed.has(h.phase))
    if (!head) for (const h of Lc.heads) if (!collapsed.has(h.phase) && (!head || h.n > head.n)) head = h
    const fitK = Math.min(availW / ((head?.w ?? b.w) + WF.PAD * 2), availH / b.h)
    let k = clamp(fitK, LEGIBILITY_FLOOR_K, 1)
    let fx = head ? head.x - WF.PAD : b.x
    if (head) {
      // pull the folded lanes just before the live column into frame while the zoom stays legible
      let j = Lc.heads.indexOf(head)
      while (j > 0 && collapsed.has(Lc.heads[j - 1].phase)) {
        const kk = Math.min(k, availW / (head.x + head.w - Lc.heads[j - 1].x + WF.PAD * 2))
        if (kk < LEGIBILITY_FLOOR_K) break
        k = kk
        j--
      }
      // a folded lane left out of frame must not peek in as a sliver at the left edge
      fx = Lc.heads[j].x - (j > 0 && collapsed.has(Lc.heads[j - 1].phase) ? 24 : WF.PAD)
    }
    return { k, x: -fx * k + 16, y: Math.max(top - b.y * k, top + (availH - b.h * k) / 2 - b.y * k) }
  }
  const bare = frame(16, 56)
  return shouldShowMinimap(b.w, b.h, W, H, bare.k) ? frame(CAM_INSET.right, CAM_INSET.bottom) : bare
}

/** Width (px) of the floating inspector overlay covering the right of the canvas (0 when docked). */
function paneInset(el: Element | null): number {
  return el ? parseFloat(getComputedStyle(el).getPropertyValue('--pane-inset')) || 0 : 0
}

/** Session flag: the graph entrance plays once per session (A-137). */
const GRAPH_SEEN_KEY = 'wf.graph.seen'
function graphSeen(): boolean {
  try { return sessionStorage.getItem(GRAPH_SEEN_KEY) === '1' } catch { return false }
}
function markGraphSeen() {
  try { sessionStorage.setItem(GRAPH_SEEN_KEY, '1') } catch { /* storage disabled: entrance simply replays */ }
}

const NO_OVERRIDES: ReadonlyMap<string, boolean> = new Map()

export function WorkflowGraph({ L: fullL, selId, focusSet, nomatch, onSelect, onExpand, onReport, replay, onReplayClose, skipEntrance }: GraphProps) {
  const { model, events, detail } = useRun()
  const runId = detail.run.id
  const runPhase = detail.run.phase
  const { theme } = useTheme()

  // ---- collapsed completed phases: defaults + per-run user overrides; the selection's phase always opens
  const [ov, setOv] = useState(() => ({ runId, map: phaseOverrideStore.get(runId) ?? NO_OVERRIDES }))
  const overrides = ov.runId === runId ? ov.map : phaseOverrideStore.get(runId) ?? NO_OVERRIDES
  const setPhaseCollapsed = useCallback((phase: string, on: boolean) => {
    const next = new Map(phaseOverrideStore.get(runId) ?? NO_OVERRIDES)
    next.set(phase, on)
    phaseOverrideStore.set(runId, next)
    setOv({ runId, map: next })
  }, [runId])
  const baseCollapsed = useMemo(() => {
    const s = defaultCollapsedPhases(fullL.heads, runPhase)
    for (const h of fullL.heads) {
      const on = overrides.get(h.phase)
      if (on === false) s.delete(h.phase)
      else if (on && isCompletedPhaseHead(h, runPhase)) s.add(h.phase)
    }
    return s
  }, [fullL.heads, runPhase, overrides])
  const selPhase = selId ? fullL.byId.get(selId)?.phase : undefined
  const collapsed = useMemo(() => {
    if (!selPhase || !baseCollapsed.has(selPhase)) return baseCollapsed
    const s = new Set(baseCollapsed)
    s.delete(selPhase)
    return s
  }, [baseCollapsed, selPhase])
  const collapsedRef = useRef(collapsed)
  collapsedRef.current = collapsed
  const baseCollapsedRef = useRef(baseCollapsed)
  baseCollapsedRef.current = baseCollapsed
  // Selecting into a folded phase opens it for good (it stays open after the selection moves on).
  useEffect(() => {
    if (selPhase && baseCollapsedRef.current.has(selPhase)) setPhaseCollapsed(selPhase, false)
  }, [selId, selPhase, setPhaseCollapsed])
  const projected = useMemo(() => projectWorkflowLayout(fullL, collapsed), [fullL, collapsed])
  const L = projected.layout
  const collapsedLanes = useMemo(() => new Map(projected.collapsedHeads.map(c => {
    const seen = new Set<string>()
    for (const a of model.detail.assignments) if (a.phase === c.head.phase) for (const f of model.workerFindings.get(a.id) ?? []) seen.add(f.id)
    return [c.head.phase, { ...c, findingsCount: seen.size }] as const
  })), [projected, model])

  const vpRef = useRef<HTMLDivElement>(null)
  const cvRef = useRef<HTMLDivElement>(null)
  const miniRef = useRef<HTMLCanvasElement>(null)
  const zlRef = useRef<HTMLSpanElement>(null)
  const tipRef = useRef<HTMLDivElement>(null)
  const cam = useRef<Cam | null>(camStore.get(runId) ?? null)
  const camAnim = useRef<() => void>(() => {})
  const [zoomTier, setZoomTier] = useState<'compact' | 'full'>('full')
  const [showMinimap, setShowMinimap] = useState(false)
  const showMiniRef = useRef(showMinimap)
  showMiniRef.current = showMinimap
  const [phaseCur, setPhaseCur] = useState(0)
  const [hover, setHover] = useState<string | null>(null)
  const hoverRef = useRef<string | null>(null)
  hoverRef.current = hover
  const Lref = useRef(L)
  Lref.current = L
  const selRef = useRef(selId)
  selRef.current = selId

  // ---- follow-live camera: on by default while work is live; any manual camera move disengages it
  const liveTarget = useMemo(() => selectFollowLiveTarget(L), [L])
  const hasLiveTarget = liveTarget.node !== null || L.heads.some(h => h.live)
  const [followLive, setFollowLiveState] = useState(() => hasLiveTarget && !selId)
  const followRef = useRef(followLive)
  const setFollow = useCallback((on: boolean) => {
    if (followRef.current === on) return
    followRef.current = on
    setFollowLiveState(on)
  }, [])
  const followRun = useRef(runId)
  useEffect(() => {
    if (followRun.current === runId) return
    followRun.current = runId
    setFollow(hasLiveTarget)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, setFollow])
  const restoredCam = useRef(cam.current !== null)

  const info = useMemo(() => nodeInfo(model, L, events), [model, L, events])

  // ---- focus: hover is transient, selection persists; digests pass an explicit set
  const focusId = hover ?? selId
  const focus = useMemo(() => {
    if (focusSet) {
      const hot = new Set<string>()
      for (const e of L.edges) if (focusSet.has(e.from) && focusSet.has(e.to)) hot.add(e.key)
      return { nodes: focusSet, edges: hot }
    }
    if (!focusId || !L.byId.has(focusId)) return null
    const { up, down } = nodeLineage(L, focusId)
    const nodes = new Set([focusId, ...up, ...down])
    // An isolated node has no lineage to highlight: dimming everything else would only hide context (A-139).
    if (nodes.size <= 1) return null
    return { nodes, edges: hotEdges(L, focusId, up, down) }
  }, [L, focusId, focusSet])
  const hotRef = useRef(focus)
  hotRef.current = focus

  // ---- replay state (frames are imperative)
  const rspan = useMemo(() => replaySpans(L, model, events), [L, model, events])
  const rspanRef = useRef(rspan)
  rspanRef.current = rspan
  const timeline = useMemo(() => ({
    facts: model.detail.facts.map(f => f.createdAt).sort((a, b) => a - b),
    verified: events.filter(e => e.kind === 'finding.verified').map(e => e.createdAt).sort((a, b) => a - b),
  }), [model, events])
  const rp = useRef({ on: false, t: 0, playing: false, speed: 2, follow: true, shown: new Set<string>() })
  const [rpUi, setRpUi] = useState({ playing: false, speed: 2 })
  const rpTimeRef = useRef<HTMLSpanElement>(null)
  const scrubRef = useRef<HTMLDivElement>(null)
  const rpStatsRef = useRef<HTMLSpanElement>(null)
  const rpRaf = useRef(0)

  // ------------------------------------------------------------ minimap
  const miniGeo = useRef({ s: 1, ox: 0, oy: 0 })
  const drawMini = useCallback(() => {
    const cvs = miniRef.current, vp = vpRef.current, c = cam.current
    if (!cvs || !vp || !c) return
    const box = cvs.parentElement!
    const W = box.clientWidth, H = box.clientHeight, dpr = window.devicePixelRatio || 1
    if (!W || !H) return
    if (cvs.width !== W * dpr || cvs.height !== H * dpr) { cvs.width = W * dpr; cvs.height = H * dpr }
    const g = cvs.getContext('2d')
    if (!g) return
    g.setTransform(dpr, 0, 0, dpr, 0, 0)
    g.clearRect(0, 0, W, H)
    const cs = getComputedStyle(vp)
    const col = (v: string) => cs.getPropertyValue(v).trim() || '#888'
    const Lc = Lref.current
    const b = bounds(Lc)
    const s = Math.min((W - 16) / b.w, (H - 16) / b.h)
    const ox = (W - b.w * s) / 2 - b.x * s, oy = (H - b.h * s) / 2 - b.y * s
    miniGeo.current = { s, ox, oy }
    const hot = hotRef.current
    const rpT = rp.current.on ? rp.current.t : null
    const sp = rspanRef.current.spans
    const shown = (id: string) => rpT == null || (sp.get(id)?.t0 ?? 0) <= rpT
    g.strokeStyle = col('--edge')
    g.lineWidth = 0.6
    g.globalAlpha = 0.7
    for (const e of Lc.edges) {
      const a = Lc.byId.get(e.from), c2 = Lc.byId.get(e.to)
      if (!a || !c2 || !shown(a.id) || !shown(c2.id)) continue
      if (hot && !hot.edges.has(e.key)) continue
      g.beginPath()
      g.moveTo(ox + (a.x + WF.NW) * s, oy + (a.y + WF.NH / 2) * s)
      g.lineTo(ox + c2.x * s, oy + (c2.y + WF.NH / 2) * s)
      g.stroke()
    }
    g.globalAlpha = 1
    const sel = selRef.current
    for (const n of allNodes(Lc)) {
      if (!shown(n.id)) continue
      const ms = n.kind === 'stack' ? n.members! : n.a ? [n.a] : []
      let f = col('--fg-4')
      if (n.kind === 'report') f = col('--fg')
      else if (ms.some(a => a.status === 'paused' || a.status === 'waiting_approval')) f = col('--warn')
      else if (ms.some(a => a.status === 'running')) f = col('--accent')
      else if (ms.some(a => a.status === 'failed')) f = col('--bad')
      else if (ms.some(a => (model.workerFindings.get(a.id) ?? []).length)) f = col('--fg-3')
      if (hot && !hot.nodes.has(n.id)) g.globalAlpha = 0.25
      if (n.id === sel) { f = col('--accent'); g.globalAlpha = 1 } else if (hot && hot.nodes.has(n.id)) f = col('--accent')
      g.fillStyle = f
      const x = ox + n.x * s, y = oy + n.y * s, w = Math.max(2, WF.NW * s), h = Math.max(1.5, WF.NH * s)
      g.beginPath()
      if (g.roundRect) g.roundRect(x, y, w, h, Math.min(2, w / 4))
      else g.rect(x, y, w, h)
      g.fill()
      g.globalAlpha = 1
    }
    const vx = -c.x / c.k, vy = -c.y / c.k, vw = vp.clientWidth / c.k, vh = vp.clientHeight / c.k
    g.strokeStyle = col('--fg-2')
    g.lineWidth = 1.25
    g.fillStyle = col('--hover')
    const rx = ox + vx * s, ry = oy + vy * s, rw = vw * s, rh = vh * s
    g.fillRect(rx, ry, rw, rh)
    g.strokeRect(rx + 0.5, ry + 0.5, rw - 1, rh - 1)
  }, [model])

  // ------------------------------------------------------------ camera
  const applyCam = useCallback(() => {
    const c = cam.current, vp = vpRef.current, cv = cvRef.current
    if (!c || !vp || !cv) return
    cv.style.transform = `translate(${c.x}px,${c.y}px) scale(${c.k})`
    vp.style.setProperty('--k', String(c.k))
    vp.style.setProperty('--bx', c.x + 'px')
    vp.style.setProperty('--by', c.y + 'px')
    if (zlRef.current) zlRef.current.textContent = Math.round(c.k * 100) + '%'
    setZoomTier(semanticZoomTier(c.k))
    const b = bounds(Lref.current)
    setShowMinimap(shouldShowMinimap(b.w, b.h, vp.clientWidth, vp.clientHeight, c.k))
    const cx = (vp.clientWidth * 0.4 - c.x) / c.k
    let cur = 0
    Lref.current.heads.forEach((h, i) => { if (h.x <= cx) cur = i })
    setPhaseCur(cur)
    camStore.set(runId, c)
    drawMini()
  }, [drawMini, runId])

  const camTo = useCallback((t: Cam, dur: number = DUR.camera) => {
    const c = cam.current
    if (!c) return
    camAnim.current()
    const from = { ...c }
    const ms = T(dur)
    if (!ms) { Object.assign(c, t); applyCam(); return }
    const t0 = performance.now()
    let raf = 0
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / ms), e = ease(p)
      c.x = from.x + (t.x - from.x) * e
      c.y = from.y + (t.y - from.y) * e
      c.k = from.k + (t.k - from.k) * e
      applyCam()
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    camAnim.current = () => cancelAnimationFrame(raf)
  }, [applyCam])

  const zoomAt = useCallback((f: number, px: number, py: number, animate: boolean) => {
    const c = cam.current
    if (!c) return
    const k = clamp(c.k * f, 0.12, 1.6)
    const wx = (px - c.x) / c.k, wy = (py - c.y) / c.k
    const t = { k, x: px - wx * k, y: py - wy * k }
    if (animate) camTo(t, 200)
    else { camAnim.current(); Object.assign(c, t); applyCam() }
  }, [applyCam, camTo])

  const fit = useCallback(() => {
    const vp = vpRef.current
    if (!vp) return
    setFollow(false)
    const b = bounds(Lref.current)
    const W = vp.clientWidth - paneInset(vp), H = vp.clientHeight - 100
    const k = clamp(Math.min(W / b.w, H / b.h), 0.12, 1)
    camTo({ k, x: (W - b.w * k) / 2 - b.x * k, y: 44 + (H - b.h * k) / 2 - b.y * k })
  }, [camTo, setFollow])

  const initialCam = useCallback((): Cam => {
    const vp = vpRef.current!
    return initialCamera(Lref.current, vp.clientWidth - paneInset(vp), vp.clientHeight, collapsedRef.current)
  }, [])

  /** Frame the live worker (or the live / largest open phase) at a legible zoom. */
  const panToLive = useCallback((dur: number = 240) => {
    const vp = vpRef.current, c = cam.current
    if (!vp || !c) return
    const Lc = Lref.current
    const { node, head: liveHead } = selectFollowLiveTarget(Lc)
    let head = liveHead
    if (!head) for (const h of Lc.heads) if (h.phase !== 'report' && !collapsedRef.current.has(h.phase) && (!head || h.n >= head.n)) head = h
    const k = Math.min(1.6, Math.max(c.k, LEGIBILITY_FLOOR_K))
    const W = vp.clientWidth - paneInset(vp), H = vp.clientHeight
    const b = bounds(Lc)
    const top = CAM_INSET.top
    const cx = node ? node.x + WF.NW / 2 : head ? head.x + head.w / 2 : b.x + b.w / 2
    const cy = node ? node.y + WF.NH / 2 : b.y + b.h / 2
    const x = b.w * k <= W - 32
      ? (W - b.w * k) / 2 - b.x * k
      : clamp(W * 0.5 - cx * k, W - 16 - (b.x + b.w) * k, 16 - b.x * k)
    const y = b.h * k <= H - top - 56
      ? top - b.y * k
      : clamp(H * 0.45 - cy * k, H - 56 - (b.y + b.h) * k, top - b.y * k)
    if (Math.abs(x - c.x) < 1 && Math.abs(y - c.y) < 1 && Math.abs(k - c.k) < 0.001) return
    camTo({ k, x, y }, dur)
  }, [camTo])

  const reveal = useCallback((id: string, center: boolean) => {
    const Lc = Lref.current, n = Lc.byId.get(id), vp = vpRef.current, c = cam.current
    if (!n || !vp || !c) return
    const W = vp.clientWidth - paneInset(vp), H = vp.clientHeight
    let k = c.k
    if (k < 0.62 && center) k = 0.8
    const sx = n.x * k + c.x, sy = n.y * k + c.y, sw = WF.NW * k, sh = WF.NH * k
    const inView = sx > 40 && sy > 50 && sx + sw < W - (showMiniRef.current ? 220 : 20) && sy + sh < H - 60
    if (inView && k === c.k && !center) return
    const b = bounds(Lc)
    const fitsV = b.h * k <= H - 60
    camTo({
      k, x: W * 0.42 - (n.x + WF.NW / 2) * k,
      y: fitsV ? (k === c.k ? c.y : Math.max(46 - b.y * k, (H - 30 - b.h * k) / 2 - b.y * k)) : H * 0.45 - (n.y + WF.NH / 2) * k,
    })
  }, [camTo])
  const revealRef = useRef(reveal)
  revealRef.current = reveal

  // mount: restore or compute the camera
  useLayoutEffect(() => {
    if (!cam.current) cam.current = initialCam()
    applyCam()
    const vp = vpRef.current!
    const ro = new ResizeObserver(() => applyCam())
    ro.observe(vp)
    return () => { ro.disconnect(); camAnim.current() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useEffect(() => { applyCam() }, [applyCam, focus, selId, theme, L])
  useEffect(() => { if (showMinimap) drawMini() }, [showMinimap, drawMini])

  // follow-live: keep the newest live worker framed as workers arrive (the first frame is the initial camera)
  const followKey = liveTarget.node ? liveTarget.node.id : liveTarget.head?.phase ?? ''
  const followMounted = useRef(false)
  useEffect(() => {
    const first = !followMounted.current
    followMounted.current = true
    if (first && !restoredCam.current) return
    if (followRef.current && !rp.current.on) panToLive()
  }, [followKey, L.W, panToLive])

  // phase nav into a folded phase: expand it, then land on its cards once the layout re-packs
  const pendingJump = useRef<string | null>(null)
  const jumpToPhase = (phase: string) => {
    setFollow(false)
    rp.current.follow = false
    if (collapsedRef.current.has(phase)) { pendingJump.current = phase; setPhaseCollapsed(phase, false); return }
    const h = Lref.current.heads.find(x => x.phase === phase), c = cam.current
    if (h && c) camTo({ k: c.k, x: 24 - h.x * c.k, y: c.y }, 240)
  }
  useEffect(() => {
    const phase = pendingJump.current
    if (!phase || collapsed.has(phase)) return
    pendingJump.current = null
    const h = L.heads.find(x => x.phase === phase), c = cam.current
    if (h && c) camTo({ k: c.k, x: 24 - h.x * c.k, y: c.y }, 240)
  }, [L, collapsed, camTo])
  const toggleFollow = () => {
    if (followRef.current) { setFollow(false); return }
    setFollow(true)
    panToLive()
  }

  // the camera eases to the selection (first mount: centre it)
  const firstReveal = useRef(true)
  useEffect(() => {
    if (!selId) return
    const center = firstReveal.current
    firstReveal.current = false
    const t = setTimeout(() => revealRef.current(selId, center), center ? 60 : 0)
    return () => clearTimeout(t)
  }, [selId])
  useEffect(() => onCameraRequest(r => { if (r.type === 'center') revealRef.current(r.id, true) }), [])

  // ------------------------------------------------------------ enter / FLIP / live updates
  const prevPos = useRef<Map<string, { x: number; y: number }> | null>(null)
  const prevEdges = useRef<Set<string>>(new Set())
  useLayoutEffect(() => {
    const cv = cvRef.current
    if (!cv) return
    const nodes = allNodes(L)
    const prev = prevPos.current
    const els = new Map<string, HTMLElement>()
    cv.querySelectorAll<HTMLElement>('[data-n]').forEach(el => els.set(el.dataset.n!, el))
    const edgeEls = new Map<string, SVGPathElement>()
    cv.querySelectorAll<SVGPathElement>('path[data-e]').forEach(el => edgeEls.set(el.dataset.e!, el))
    const W = L.W || 1
    const rm = reducedMotion()
    // Edges fade in (opacity only); the stroke draw is reserved for Replay (A-137).
    const draw = (el: SVGPathElement, _causal: boolean, delay: number) => {
      el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 150, delay, easing: EASE_CSS, fill: 'backwards' })
    }
    if (!prev) {
      // Entrance settles within 300ms and plays once per session, never on the L shortcut.
      const skip = rm || skipEntrance || graphSeen()
      markGraphSeen()
      if (!skip) {
        for (const n of nodes) {
          els.get(n.id)?.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }],
            { duration: 180, delay: Math.min(90, Math.round(n.x / W * 90)), easing: EASE_CSS, fill: 'backwards' })
        }
        for (const e of L.edges) {
          const a = L.byId.get(e.from)
          const el = edgeEls.get(e.key)
          if (a && el) draw(el, e.kind === 'causal', Math.min(90, Math.round(a.x / W * 90)))
        }
      }
    } else if (!rm) {
      const moved = new Set<string>()
      let firstNew: string | null = null
      const grpIndex = new Map<string, number>()
      for (const n of nodes) {
        const el = els.get(n.id)
        if (!el) continue
        const p = prev.get(n.id)
        if (p) {
          const dx = p.x - n.x, dy = p.y - n.y
          if (dx || dy) {
            moved.add(n.id)
            el.animate([{ transform: `translate(${dx}px,${dy}px)` }, { transform: 'none' }], { duration: 340, easing: EASE_CSS })
          }
          continue
        }
        moved.add(n.id)
        // members fly out of their stack; a re-collapsed stack gathers from its first member
        const gid = n.kind === 'worker' ? L.stacks.of.get(n.id) : undefined
        const origin = gid && prev.get(gid) ? prev.get(gid)! : n.kind === 'stack' ? prev.get(n.g!.members[0]) : undefined
        if (origin) {
          const i = gid ? (grpIndex.set(gid, (grpIndex.get(gid) ?? -1) + 1), grpIndex.get(gid)!) : 0
          if (gid && i === 0) firstNew = n.id
          el.animate([{ transform: `translate(${origin.x - n.x}px,${origin.y - n.y}px) scale(.92)`, opacity: 0 }, { transform: 'none', opacity: 1 }],
            { duration: 360, delay: i * 14, easing: EASE_CSS, fill: 'backwards' })
        } else {
          // a new worker arrived over SSE
          el.animate([{ opacity: 0, transform: 'scale(.94) translateY(6px)' }, { opacity: 1, transform: 'none' }], { duration: 320, easing: EASE_CSS, fill: 'backwards' })
        }
      }
      for (const e of L.edges) {
        const el = edgeEls.get(e.key)
        if (!el) continue
        if (!prevEdges.current.has(e.key)) draw(el, e.kind === 'causal', moved.has(e.from) || moved.has(e.to) ? 220 : 0)
        else if (moved.has(e.from) || moved.has(e.to)) el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 260, delay: 200, fill: 'backwards' })
      }
      if (firstNew) { const id = firstNew; setTimeout(() => revealRef.current(id, false), T(40)) }
    }
    prevPos.current = new Map(nodes.map(n => [n.id, { x: n.x, y: n.y }]))
    prevEdges.current = new Set(L.edges.map(e => e.key))
    if (rp.current.on) applyReplay(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [L])

  // ------------------------------------------------------------ replay
  const applyReplay = useCallback((force: boolean) => {
    const cv = cvRef.current
    if (!cv || !rp.current.on) return
    const Lc = Lref.current
    const { spans, t0, t1 } = rspanRef.current
    const t = rp.current.t
    let started = 0
    for (const n of allNodes(Lc)) {
      const el = cv.querySelector<HTMLElement>(`[data-n="${CSS.escape(n.id)}"]`)
      const s = spans.get(n.id)
      if (!el || !s) continue
      const vis = s.t0 <= t
      let state = !vis ? 'hidden' : n.kind === 'report' || n.kind === 'queue' ? 'now' : t < s.t1 ? 'live' : 'now'
      if (state === 'live' && !Number.isFinite(s.t1) && t >= t1 - 1) state = 'now'
      if (el.dataset.rp !== state) el.dataset.rp = state
      if (n.kind === 'worker' && vis) started++
      if (n.kind === 'stack' && s.spans) {
        const k = s.spans.filter(x => x[0] <= t).length
        started += k
        const idEl = el.querySelector<HTMLElement>('[data-wf-id]')
        const txt = (k < s.spans.length ? k + ' of ' : '') + s.spans.length + ' workers'
        if (idEl && idEl.textContent !== txt) idEl.textContent = txt
        el.querySelectorAll<HTMLElement>('[data-wf-ticks] i').forEach((ti, j) => { ti.style.opacity = s.spans![j] && s.spans![j][0] <= t ? '' : '0.2' })
      }
    }
    const shown = rp.current.shown
    for (const e of Lc.edges) {
      const el = cv.querySelector<SVGPathElement>(`path[data-e="${CSS.escape(e.key)}"]`)
      if (!el) continue
      const a = spans.get(e.from), b = spans.get(e.to)
      const vis = !!a && !!b && a.t0 <= t && b.t0 <= t
      if (vis && !shown.has(e.key)) {
        shown.add(e.key)
        el.removeAttribute('data-rp')
        if (!force && !reducedMotion() && e.kind !== 'causal') {
          el.animate([{ strokeDasharray: '1', strokeDashoffset: '1' }, { strokeDasharray: '1', strokeDashoffset: '0' }], { duration: 600, easing: EASE_CSS })
        }
      } else if (!vis) { shown.delete(e.key); el.dataset.rp = 'hidden' }
    }
    const count = (arr: number[]) => { let lo = 0, hi = arr.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] <= t) lo = mid + 1; else hi = mid } return lo }
    const p = (t - t0) / (t1 - t0 || 1)
    if (rpTimeRef.current) rpTimeRef.current.textContent = fmtRel(t, t0)
    scrubRef.current?.style.setProperty('--p', clamp(p, 0, 1).toFixed(4))
    if (rpStatsRef.current) {
      rpStatsRef.current.innerHTML = `<span><b>${started}</b> / ${model.detail.assignments.length} workers</span><span><b>${fmtN(count(timeline.facts))}</b> facts</span><span><b>${count(timeline.verified)}</b> verified</span>`
    }
    // follow the frontier until the user pans
    if (!force && rp.current.follow) {
      const c = cam.current, vp = vpRef.current
      if (c && vp) {
        let fx = -1e9
        for (const n of allNodes(Lc)) { const s = spans.get(n.id); if (s && s.t0 <= t) fx = Math.max(fx, n.x + WF.NW) }
        if (fx > 0) {
          const b = bounds(Lc)
          const want = Math.min(16 - b.x * c.k, vp.clientWidth * 0.7 - fx * c.k)
          if (Math.abs(want - c.x) > 0.5) { c.x += (want - c.x) * (reducedMotion() ? 1 : 0.1); applyCam() }
        }
      }
    }
    drawMini()
  }, [applyCam, drawMini, model, timeline])
  const applyReplayRef = useRef(applyReplay)
  applyReplayRef.current = applyReplay

  const loop = useCallback(() => {
    cancelAnimationFrame(rpRaf.current)
    let last = performance.now()
    const step = (now: number) => {
      const r = rp.current
      if (!r.on || !r.playing) return
      const { t0, t1 } = rspanRef.current
      const dt = now - last
      last = now
      r.t = Math.min(t1, r.t + dt * (t1 - t0) / 16000 * r.speed)
      applyReplayRef.current(false)
      if (r.t >= t1) { r.playing = false; setRpUi(u => ({ ...u, playing: false })); return }
      rpRaf.current = requestAnimationFrame(step)
    }
    rpRaf.current = requestAnimationFrame(step)
  }, [])

  const clearReplay = useCallback(() => {
    const cv = cvRef.current
    if (!cv) return
    cv.querySelectorAll<HTMLElement>('[data-rp]').forEach(el => el.removeAttribute('data-rp'))
    cv.querySelectorAll<HTMLElement>('[data-wf-id][data-def]').forEach(el => { el.textContent = el.dataset.def ?? el.textContent })
    cv.querySelectorAll<HTMLElement>('[data-wf-ticks] i').forEach(el => { el.style.opacity = '' })
  }, [])

  useEffect(() => {
    if (!replay) return
    const { t0 } = rspanRef.current
    rp.current = { on: true, t: t0, playing: true, speed: 2, follow: true, shown: new Set() }
    setFollow(false)
    setRpUi({ playing: true, speed: 2 })
    applyReplayRef.current(true)
    // camera: whole height, start at the left edge
    const vp = vpRef.current, c = cam.current
    if (vp && c) {
      const b = bounds(Lref.current)
      const H = vp.clientHeight
      const k = clamp((H - 150) / b.h, 0.45, 0.86)
      camTo({ k, x: 16 - b.x * k, y: Math.max(46 - b.y * k, (H - 80 - b.h * k) / 2 - b.y * k) }, 420)
    }
    const start = setTimeout(loop, T(420))
    return () => {
      clearTimeout(start)
      cancelAnimationFrame(rpRaf.current)
      rp.current.on = false
      clearReplay()
      drawMini()
    }
  }, [replay, loop, camTo, clearReplay, drawMini, setFollow])

  const togglePlay = useCallback(() => {
    const r = rp.current
    if (!r.on) return
    if (r.playing) { r.playing = false; cancelAnimationFrame(rpRaf.current) }
    else {
      const { t0, t1 } = rspanRef.current
      if (r.t >= t1) { r.t = t0; r.shown = new Set(); r.follow = true; applyReplayRef.current(true) }
      r.playing = true
      loop()
    }
    setRpUi(u => ({ ...u, playing: r.playing }))
  }, [loop])
  const setSpeed = (s: number) => { rp.current.speed = s; setRpUi(u => ({ ...u, speed: s })) }
  const scrubTo = (clientX: number) => {
    const el = scrubRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const { t0, t1 } = rspanRef.current
    rp.current.t = t0 + clamp((clientX - r.left) / r.width, 0, 1) * (t1 - t0)
    rp.current.follow = true
    applyReplayRef.current(true)
    // keep the camera on the frontier while scrubbing
    applyReplayRef.current(false)
  }

  // ------------------------------------------------------------ pointer: pan, hover, click
  const drag = useRef<{ x: number; y: number; cx: number; cy: number; moved: boolean; id: number; node: string | null; expand: string | null } | null>(null)
  const hideTip = () => tipRef.current?.removeAttribute('data-open')
  const showTip = (n: WfNode, x: number, y: number) => {
    const tip = tipRef.current
    if (!tip) return
    const [b, o] = tip.children as unknown as HTMLElement[]
    if (n.kind === 'worker') { b.textContent = n.a!.title; o.textContent = firstSentence(n.a!.objective) }
    else if (n.kind === 'stack') { b.textContent = n.g!.title + ' × ' + n.members!.length; o.textContent = 'Stacked because the workers share one objective template. Click to inspect, Expand to lay them out.' }
    else if (n.kind === 'queue') { b.textContent = plural(n.steps!.length, 'chain step') + ' queued'; o.textContent = 'Planned by the coordinator, not yet dispatched to a worker. Click to review or cancel them.' }
    else { b.textContent = 'Report'; o.textContent = 'Open the report' }
    const vw = window.innerWidth
    tip.style.left = Math.min(x + 14, vw - 316) + 'px'
    tip.style.top = (y + 16) + 'px'
    tip.dataset.open = ''
  }
  const onPointerDown = (e: RPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return
    const c = cam.current
    if (!c) return
    const t = e.target as Element
    if (t.closest('[data-wf-float]')) return
    hideTip()
    drag.current = {
      x: e.clientX, y: e.clientY, cx: c.x, cy: c.y, moved: false, id: e.pointerId,
      node: (t.closest('[data-n]') as HTMLElement | null)?.dataset.n ?? null,
      expand: (t.closest('[data-wfexpand]') as HTMLElement | null)?.dataset.wfexpand ?? null,
    }
    camAnim.current()
  }
  const onPointerMove = (e: RPointerEvent<HTMLDivElement>) => {
    const d = drag.current
    const c = cam.current
    if (d && c) {
      const dx = e.clientX - d.x, dy = e.clientY - d.y
      if (!d.moved && Math.hypot(dx, dy) > 4) {
        d.moved = true
        vpRef.current?.setPointerCapture(d.id)
        vpRef.current?.setAttribute('data-panning', '')
        hideTip()
        if (hoverRef.current) setHover(null)
      }
      if (d.moved) { c.x = d.cx + dx; c.y = d.cy + dy; rp.current.follow = false; setFollow(false); applyCam() }
      return
    }
    const t = e.target as Element
    const el = t.closest('[data-n]') as HTMLElement | null
    const id = el && !t.closest('[data-wf-float]') ? el.dataset.n! : null
    if (id !== hoverRef.current) setHover(id)
    const n = id ? Lref.current.byId.get(id) : null
    if (n) showTip(n, e.clientX, e.clientY)
    else hideTip()
  }
  const onPointerUp = () => {
    const d = drag.current
    drag.current = null
    vpRef.current?.removeAttribute('data-panning')
    if (!d || d.moved) return
    if (d.expand) { onExpand(d.expand, true); return }
    if (d.node === 'report') { onReport(); return }
    if (d.node) { setFollow(false); onSelect(d.node === selRef.current ? null : d.node); return }
    if (selRef.current) onSelect(null)
  }

  // wheel: zoom around the cursor; shift+wheel or trackpad pans (non-passive)
  useEffect(() => {
    const vp = vpRef.current
    if (!vp) return
    const onWheel = (e: WheelEvent) => {
      if ((e.target as Element).closest('[data-wf-float]')) return
      e.preventDefault()
      hideTip()
      camAnim.current()
      rp.current.follow = false
      setFollow(false)
      const c = cam.current
      if (!c) return
      const r = vp.getBoundingClientRect()
      if (!e.ctrlKey && (e.shiftKey || Math.abs(e.deltaX) > Math.abs(e.deltaY) || (e.deltaMode === 0 && Math.abs(e.deltaY) < 40 && e.deltaX !== 0))) {
        c.x -= e.shiftKey ? e.deltaY : e.deltaX
        if (!e.shiftKey) c.y -= 0
        applyCam()
        return
      }
      const f = Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0018))
      zoomAt(f, e.clientX - r.left, e.clientY - r.top, false)
    }
    vp.addEventListener('wheel', onWheel, { passive: false })
    return () => vp.removeEventListener('wheel', onWheel)
  }, [applyCam, zoomAt, setFollow])

  // minimap: click or drag to move
  const miniDown = useRef(false)
  const miniGo = (e: RPointerEvent<HTMLDivElement>, animate: boolean) => {
    const c = cam.current, vp = vpRef.current
    if (!c || !vp) return
    const r = e.currentTarget.getBoundingClientRect()
    const { s, ox, oy } = miniGeo.current
    const wx = (e.clientX - r.left - ox) / s, wy = (e.clientY - r.top - oy) / s
    const t = { k: c.k, x: (vp.clientWidth - paneInset(vp)) / 2 - wx * c.k, y: vp.clientHeight / 2 - wy * c.k }
    rp.current.follow = false
    setFollow(false)
    if (animate) camTo(t, 240)
    else { camAnim.current(); Object.assign(c, t); applyCam() }
  }

  // ------------------------------------------------------------ keyboard
  const readingOrder = useMemo(() => L.nodes.slice().sort((a, b) => a.x - b.x || a.y - b.y), [L])
  const move = (dir: 'left' | 'right' | 'up' | 'down') => {
    const cur = selId ? L.byId.get(selId) : undefined
    if (!cur) { if (readingOrder[0]) onSelect(readingOrder[0].id); return }
    let best: WfNode | null = null, bs = 1e12
    for (const n of L.nodes) {
      if (n === cur) continue
      const dx = n.x - cur.x, dy = n.y - cur.y
      let s: number
      if (dir === 'right') { if (dx <= 0) continue; s = dx + Math.abs(dy) * 2.2 }
      else if (dir === 'left') { if (dx >= 0) continue; s = -dx + Math.abs(dy) * 2.2 }
      else if (dir === 'down') { if (dy <= 0 || Math.abs(dx) > WF.NW / 2) continue; s = dy + Math.abs(dx) }
      else { if (dy >= 0 || Math.abs(dx) > WF.NW / 2) continue; s = -dy + Math.abs(dx) }
      if (s < bs) { bs = s; best = n }
    }
    if (best) onSelect(best.id)
  }
  const step = (d: number) => {
    const i = selId ? readingOrder.findIndex(n => n.id === selId) : -1
    const next = readingOrder[i < 0 ? (d > 0 ? 0 : readingOrder.length - 1) : clamp(i + d, 0, readingOrder.length - 1)]
    if (next) onSelect(next.id)
  }
  const centerZoom = (f: number) => { const vp = vpRef.current; if (vp) zoomAt(f, vp.clientWidth / 2, vp.clientHeight / 2, true) }
  useShortcuts([
    { key: 'ArrowRight', run: () => move('right') },
    { key: 'ArrowLeft', run: () => move('left') },
    { key: 'ArrowDown', run: () => move('down') },
    { key: 'ArrowUp', run: () => move('up') },
    { key: 'j', run: () => step(1) },
    { key: 'k', run: () => step(-1) },
    { key: ['+', '='], run: () => centerZoom(1.2) },
    { key: ['-', '_'], run: () => centerZoom(1 / 1.2) },
    { key: ['0', '!'], run: fit },
    { key: ['Enter', 'o'], run: () => { if (selId) reveal(selId, true); else if (readingOrder[0]) onSelect(readingOrder[0].id) } },
    { key: ' ', run: () => { if (!replay) return false; togglePlay() } },
  ])

  // ------------------------------------------------------------ render
  const reportSub = L.report && model.report ? (model.report.partial ? 'Partial report' : 'Final report') + ' · ' + plural(model.findings.length, 'finding') : ''
  const nLinks = L.edges.filter(e => e.kind !== 'report').length
  const steps = model.detail.chainSteps
  const stepsDone = steps.filter(s => s.status === 'complete').length
  const svgW = L.W + 200, svgH = L.H + 200
  const zBtn = cn(runIconBtn({ size: 'sm' }), 'px-1.5')
  return <div
    className="group/wf @container/wf relative flex min-h-0 flex-1 flex-col [contain:paint]"
    data-focus={focus ? '' : undefined}
    data-lod={zoomTier === 'compact' ? '' : undefined}
    data-zoom-tier={zoomTier}
    data-follow-live={followLive ? '' : undefined}
    data-replaying={replay ? '' : undefined}
  >
    <div
      ref={vpRef}
      className="relative min-h-0 flex-1 cursor-grab touch-none overflow-hidden bg-canvas outline-none focus-visible:shadow-[inset_0_0_0_2px_var(--accent-line)] data-[panning]:cursor-grabbing"
      style={{
        backgroundImage: 'radial-gradient(var(--dot) 1px, transparent 1.2px)',
        backgroundSize: 'calc(20px * var(--k, 1)) calc(20px * var(--k, 1))',
        backgroundPosition: 'var(--bx, 0) var(--by, 0)',
      }}
      tabIndex={0}
      aria-label="Workflow graph. Arrow keys move between workers."
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onScroll={e => { e.currentTarget.scrollLeft = 0; e.currentTarget.scrollTop = 0 }}
      onPointerCancel={() => { drag.current = null; vpRef.current?.removeAttribute('data-panning') }}
      onPointerLeave={() => { if (!drag.current && hoverRef.current) setHover(null); hideTip() }}
      onDoubleClick={e => { const el = (e.target as Element).closest('[data-wf-kind="stack"]') as HTMLElement | null; if (el?.dataset.n) onExpand(el.dataset.n, true) }}
    >
      <div ref={cvRef} className="absolute left-0 top-0 origin-top-left will-change-transform" style={{ '--nw': WF.NW + 'px', '--nh': WF.NH + 'px' } as CSSProperties}>
        <svg className="pointer-events-none absolute left-0 top-0 overflow-visible" width={svgW} height={svgH} aria-hidden="true">
          <defs>
            {(['rw-wf-ah', 'rw-wf-ahh'] as const).map(id => <marker key={id} id={id} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 1 7 4 0 7Z" className={id === 'rw-wf-ah' ? 'fill-[var(--edge)]' : 'fill-accent'} /></marker>)}
          </defs>
          {L.edges.map(e => <Edge key={e.key} e={e} d={edgePath(L, e)} hot={!!focus?.edges.has(e.key)} />)}
        </svg>
        {L.heads.map(h => {
          const label = h.phase === 'report' ? 'Report' : PHASE_LABEL[h.phase] ?? h.phase
          const lane = collapsedLanes.get(h.phase)
          if (lane) {
            const count = lane.workerCount
            const meta = [plural(h.n, 'worker') + ' complete', h.earlier ? h.earlier + ' earlier' : '', lane.findingsCount ? plural(lane.findingsCount, 'finding') : ''].filter(Boolean).join(' · ')
            return <div key={h.phase} className="absolute px-0.5" style={{ left: h.x, top: 0, width: h.w, height: Math.max(L.H, WF.HH + WF.NH) }} data-wf-collapsed-phase={h.phase}>
              <span className="flex items-baseline gap-2 whitespace-nowrap text-[13px] font-semibold text-fg">
                {label}<span className="text-[12px] font-normal text-fg-subtle tabular-nums">Done</span>
              </span>
              <span className="mt-1.5 block h-[3px] overflow-hidden rounded-[2px] bg-line-2"><i className="block h-full w-full bg-fg-subtle" /></span>
              <span className="pointer-events-none absolute inset-x-0.5 bottom-0 rounded-[9px] border border-dashed border-line-2" style={{ top: WF.HH }} aria-hidden="true" />
              <button
                type="button"
                data-wf-float=""
                data-wf-phase-toggle={h.phase}
                aria-expanded="false"
                aria-label={`Expand ${label}: ${plural(count, 'worker')}, all complete`}
                title="Expand this completed phase"
                className="absolute inset-x-0.5 flex h-auto min-h-[var(--nh)] cursor-pointer flex-col items-start gap-1 whitespace-normal rounded-[9px] border-0 bg-panel px-3 py-2.5 text-left font-sans shadow-surface transition-[box-shadow] duration-[var(--d1)] ease-kovo hover:bg-panel hover:shadow-[0_0_0_1px_var(--line-strong),0_4px_12px_-4px_rgba(0,0,0,.14)]"
                style={{ top: WF.HH }}
                onClick={() => { setFollow(false); setPhaseCollapsed(h.phase, false) }}
              >
                <span className="flex w-full min-w-0 items-center gap-1.5 text-[13px] font-medium leading-[18px] text-fg group-data-[lod]/wf:text-[17px] group-data-[lod]/wf:leading-[22px]">
                  <span className="inline-flex flex-none text-ok"><Icon name="check" /></span>
                  <span className="min-w-0 truncate">{label} · <span className="tabular-nums">{count}</span></span>
                </span>
                <span className="text-[11.5px] leading-4 text-fg-subtle group-data-[lod]/wf:hidden">{meta}</span>
                <span className="mt-auto inline-flex items-center gap-1 text-[11.5px] font-medium leading-4 text-accent group-data-[lod]/wf:hidden">Expand<Icon name="chevR" size={11} /></span>
              </button>
            </div>
          }
          const isCur = h.live && h.phase === detail.run.phase
          const foldable = isCompletedPhaseHead(h, runPhase)
          return <div key={h.phase} className="absolute flex flex-col gap-1.5 px-0.5" style={{ left: h.x, top: 0, width: h.w }}>
            <span className="flex items-baseline gap-2 whitespace-nowrap text-[13px] font-semibold text-fg">
              {label}
              <span className="text-[12px] font-normal text-fg-subtle tabular-nums">
                {h.phase === 'report' ? 'v' + (model.report?.version ?? '') : h.n ? h.done + ' of ' + h.n + ' complete' : 'No workers'}
                {h.earlier ? ' · ' + h.earlier + ' earlier' : ''}
              </span>
              {isCur && <span className="ml-0.5 text-[11px] font-medium text-accent">Current</span>}
              {foldable && <button
                type="button"
                data-wf-float=""
                data-wf-phase-toggle={h.phase}
                aria-expanded="true"
                aria-label={`Collapse ${label}`}
                title="Fold this completed phase into a summary lane"
                className="ml-auto inline-flex h-5 flex-none cursor-pointer items-center gap-1 self-center rounded-[5px] border-0 bg-transparent px-1.5 font-sans text-[11px] font-normal text-fg-subtle shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg"
                onClick={() => {
                  if (selPhase === h.phase) onSelect(null)
                  setPhaseCollapsed(h.phase, true)
                }}
              >
                <Icon name="minus" size={11} />Collapse
              </button>}
            </span>
            <span className="h-[3px] overflow-hidden rounded-[2px] bg-line-2">
              <i
                className={cn('block h-full origin-left transition-transform duration-[var(--d3)] ease-kovo', isCur ? 'bg-accent' : 'bg-fg-subtle')}
                style={{ transform: `scaleX(${h.n ? h.done / h.n : 0})` }}
              />
            </span>
            {h.expanded.map(g => <button
              key={g.id}
              type="button"
              data-wf-float=""
              className="mt-0.5 inline-flex h-5 cursor-pointer items-center gap-[5px] self-start rounded-[5px] border-0 bg-panel pl-[5px] pr-[7px] font-sans text-[11px] font-normal text-fg-muted shadow-hairline transition-colors duration-[var(--d1)] hover:bg-panel hover:text-fg"
              onClick={() => onExpand(g.id, false)}
            >
              <Icon name="minus" size={11} />Collapse {g.title.toLowerCase()} · {g.members.length}
            </button>)}
          </div>
        })}
        {allNodes(L).map(n => <NodeCard
          key={n.id}
          n={n}
          info={info.get(n.id)}
          flags={{
            sel: n.id === selId,
            hot: !!focus?.nodes.has(n.id),
            nomatch: nomatch.has(n.id),
            member: n.kind === 'worker' && L.stacks.of.has(n.id),
            hist: n.kind === 'worker' && L.history.has(n.id),
          }}
          reportSub={reportSub}
        />)}
      </div>
      {!L.nodes.length && <div className="pointer-events-none absolute inset-0 flex items-center justify-center"><span className="text-[12.5px] text-fg-subtle">No workers match.</span></div>}
    </div>

    <div className="pointer-events-none absolute left-3 right-[calc(var(--pane-inset,0px)+12px)] top-2.5 z-[3] flex items-center justify-between gap-2" data-wf-topbar="">
      <div
        data-wf-float=""
        className="pointer-events-auto flex h-7 min-w-0 items-center gap-0 overflow-x-auto overflow-y-hidden rounded-lg bg-raise px-[3px] shadow-popover [scrollbar-width:none]"
        role="navigation"
        aria-label="Phases"
      >
        {L.heads.map((h, i) => <span key={h.phase} className="contents">
          {i > 0 && <span className="flex flex-none text-fg-faint"><Icon name="chevR" /></span>}
          <button
            type="button"
            className={cn(
              'inline-flex h-[22px] flex-none cursor-pointer items-center gap-[5px] whitespace-nowrap rounded-[5px] border-0 px-[7px] font-sans text-[12px] font-normal shadow-none transition-[background-color,color] duration-[var(--d1)]',
              i === phaseCur
                ? 'bg-press text-fg hover:bg-press'
                : 'bg-transparent text-fg-subtle hover:bg-hover hover:text-fg',
            )}
            data-wf-phase-nav={h.phase}
            data-wf-phase-collapsed={collapsed.has(h.phase) ? '' : undefined}
            onClick={() => jumpToPhase(h.phase)}
          >
            {h.phase === 'report' ? 'Report' : PHASE_LABEL[h.phase] ?? h.phase}
            {h.phase !== 'report' && <span className={cn('text-[11px] tabular-nums', i === phaseCur ? 'text-fg-subtle' : 'text-fg-faint')}>{h.n + h.earlier}</span>}
          </button>
        </span>)}
      </div>
      <button
        type="button"
        data-wf-float=""
        data-testid="wf-follow-live"
        aria-pressed={followLive}
        title={followLive ? 'Following the newest live worker · pan or zoom to stop' : 'Follow the newest live worker'}
        className={cn(
          'pointer-events-auto inline-flex h-7 flex-none cursor-pointer items-center gap-2 whitespace-nowrap rounded-lg border-0 px-2.5 font-sans text-[12px] font-medium transition-[background-color,color,box-shadow] duration-[var(--d1)] ease-kovo',
          followLive
            ? 'bg-accent-soft text-accent shadow-[inset_0_0_0_1px_var(--accent-line),var(--shadow-pop)] hover:bg-accent-soft'
            : 'bg-raise text-fg-muted shadow-popover hover:bg-raise hover:text-fg',
        )}
        onClick={toggleFollow}
      >
        {followLive ? <><LiveDot />Following live</> : <><Icon name="follow" />Follow live</>}
      </button>
    </div>

    <div data-wf-float="" className="absolute bottom-3 left-3 z-[3] flex items-end gap-1.5 group-data-[replaying]/wf:hidden">
      <div className="flex h-[30px] items-center gap-0.5 rounded-lg bg-raise px-[3px] shadow-popover">
        <button type="button" className={zBtn} title="Zoom out (−)" aria-label="Zoom out" onClick={() => centerZoom(1 / 1.2)}><Icon name="minus" /></button>
        <span className="min-w-11 text-center text-[12px] text-fg-muted tabular-nums" ref={zlRef}>100%</span>
        <button type="button" className={zBtn} title="Zoom in (+)" aria-label="Zoom in" onClick={() => centerZoom(1.2)}><Icon name="plus" /></button>
        <button type="button" className={zBtn} title="Fit graph (0 / ⇧1)" aria-label="Fit graph" onClick={fit}><Icon name="fit" /></button>
      </div>
      <div className="flex h-[30px] items-center gap-3 whitespace-nowrap rounded-lg bg-raise px-2.5 text-[11.5px] text-fg-subtle shadow-popover @max-[560px]/wf:hidden">
        {([['Handoff', undefined], ['Causal · facts', '4 3']] as const).map(([lbl, dash]) => (
          <span key={lbl} className="inline-flex items-center gap-1.5"><svg width="22" height="6" aria-hidden="true"><path d="M1 3h20" stroke="var(--fg-3)" strokeWidth="1.4" strokeDasharray={dash} /></svg>{lbl}</span>
        ))}
        <span className="text-fg-faint tabular-nums @max-[720px]/wf:hidden">{plural(nLinks, 'link')}{steps.length > 0 && <> · {stepsDone}/{steps.length} steps</>}</span>
      </div>
    </div>

    {showMinimap && <div
      data-wf-float=""
      data-testid="wf-minimap"
      className="absolute bottom-3 right-[calc(var(--pane-inset,0px)+12px)] z-[3] h-[124px] w-[200px] cursor-pointer overflow-hidden rounded-lg bg-raise shadow-popover @max-[720px]/wf:h-24 @max-[720px]/wf:w-[150px]"
      title="Minimap: click or drag to move"
      onPointerDown={e => { miniDown.current = true; e.currentTarget.setPointerCapture(e.pointerId); miniGo(e, true) }}
      onPointerMove={e => { if (miniDown.current) miniGo(e, false) }}
      onPointerUp={() => { miniDown.current = false }}
    >
      <canvas ref={miniRef} className="block size-full" />
    </div>}

    {replay && <div
      data-wf-float=""
      className={cn(
        'absolute bottom-3 left-3 z-[4] flex h-12 items-center gap-2.5 rounded-card bg-raise pl-1.5 pr-2.5 shadow-popover',
        showMinimap ? 'right-[calc(var(--pane-inset,0px)+224px)] @max-[720px]/wf:right-[calc(var(--pane-inset,0px)+174px)]' : 'right-[calc(var(--pane-inset,0px)+12px)]',
      )}
      role="group"
      aria-label="Replay"
    >
      <button
        type="button"
        className="flex size-8 flex-none cursor-pointer items-center justify-center rounded-lg border-0 bg-transparent text-fg shadow-none transition-colors duration-[var(--d1)] hover:bg-hover"
        title="Play / pause (Space)"
        aria-label={rpUi.playing ? 'Pause' : 'Play'}
        onClick={togglePlay}
      >
        <Icon name={rpUi.playing ? 'pause' : 'play'} />
      </button>
      <span className="min-w-[58px] font-mono text-[12px] text-fg tabular-nums" ref={rpTimeRef}>+00:00</span>
      <div
        className="relative h-8 min-w-[120px] flex-1 cursor-pointer"
        ref={scrubRef}
        onPointerDown={e => { e.currentTarget.setPointerCapture(e.pointerId); scrubTo(e.clientX) }}
        onPointerMove={e => { if (e.buttons & 1) scrubTo(e.clientX) }}
      >
        <span className="absolute inset-x-0 top-[15px] h-[3px] rounded-[2px] bg-line-2" />
        <span
          className="absolute left-0 top-[15px] h-[3px] w-full origin-left rounded-[2px] bg-fg-muted"
          style={{ transform: 'scaleX(var(--p, 0))' }}
        />
        {[...rspan.spans.entries()].filter(([id]) => id !== 'report').map(([id, s]) => (
          <i key={id} className="absolute top-2 h-1 w-px bg-fg-faint" style={{ left: ((s.t0 - rspan.t0) / (rspan.t1 - rspan.t0 || 1) * 100).toFixed(2) + '%' }} />
        ))}
        {timeline.verified.map((t, i) => (
          <i key={'f' + i} className="absolute top-5 h-[7px] w-px bg-fg-muted" title="Finding verified" style={{ left: ((t - rspan.t0) / (rspan.t1 - rspan.t0 || 1) * 100).toFixed(2) + '%' }} />
        ))}
        <span
          className="absolute top-2.5 -ml-[6.5px] size-[13px] rounded-full bg-panel shadow-[0_0_0_1.5px_var(--fg),0_1px_3px_rgba(0,0,0,.2)]"
          style={{ left: 'calc(var(--p, 0) * 100%)' }}
        />
      </div>
      <span
        className="flex gap-2.5 whitespace-nowrap text-[11.5px] text-fg-subtle tabular-nums [&_b]:font-medium [&_b]:text-fg-muted @max-[720px]/wf:[&>span:nth-child(n+2)]:hidden @max-[560px]/wf:hidden"
        ref={rpStatsRef}
      />
      <div className="inline-flex h-[26px] flex-none items-center rounded-control bg-sunk p-0.5 text-[11.5px] shadow-[inset_0_0_0_1px_var(--line)]">
        {[1, 2, 4].map(s => (
          <button
            key={s}
            type="button"
            className={cn(
              'inline-flex h-[22px] cursor-pointer items-center justify-center rounded-[4px] border-0 px-2 font-sans text-[11.5px] font-medium transition-[background-color,color,box-shadow] duration-[var(--d1)]',
              rpUi.speed === s
                ? 'bg-raise text-fg shadow-[0_0_0_1px_var(--line-2),0_1px_2px_rgba(0,0,0,.05)] hover:bg-raise'
                : 'bg-transparent text-fg-muted shadow-none hover:bg-transparent hover:text-fg',
            )}
            onClick={() => setSpeed(s)}
          >
            {s}×
          </button>
        ))}
      </div>
      <button type="button" className={runIconBtn()} title="Close replay (⇧R)" aria-label="Close replay" onClick={onReplayClose}><Icon name="close" /></button>
    </div>}

    <div
      className="pointer-events-none fixed z-[80] max-w-[300px] translate-y-0.5 rounded-[7px] bg-raise px-[9px] py-[7px] text-[12px] leading-[17px] text-fg-muted opacity-0 shadow-popover transition-[opacity,translate] duration-[var(--d1)] data-[open]:translate-y-0 data-[open]:opacity-100 [&_b]:font-medium [&_b]:text-fg"
      ref={tipRef}
      role="tooltip"
    >
      <b />
      <div className="mt-[3px] text-fg-subtle" />
    </div>
  </div>
}

/** Small exported helpers for the inspector. */
