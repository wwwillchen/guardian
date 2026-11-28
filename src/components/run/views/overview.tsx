// Overview: state-aware run hero, written verdict, severity tally, confidence meter, key stats,
// queue summary, top findings, workflow summary, requests/min traffic sparkline, coverage.
// Waiting runs render the consent sheet.
import { useEffect, useMemo, useState } from 'react'
import type { KeyboardEvent, PointerEvent as ReactPointerEvent } from 'react'
import { runLifecycleMeta, runLifecycleOf, runModeMeta, runModeOf } from '../../run-state.ts'
import type { LifecycleTone } from '../../run-state.ts'
import { useRun, useRunModel, useVerdict } from '../data.tsx'
import { useDecisions } from '../decisions.tsx'
import { FindingTitle, HostLabel } from '../display.tsx'
import { fmtDate, fmtN, fmtTime, host, plural } from '../format.ts'
import { CovSwatch, LiveDot, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { openBudgetPopover } from '../header.tsx'
import { Icon } from '../icons.tsx'
import { normFStatus, PHASE_LABEL, SEV, SEV_COL, SEV_LABEL, stLabel } from '../meta.ts'
import type { ViewId } from '../meta.ts'
import { buildTrafficSparkline, bySeriousness, coverageCounts, deriveRunHero } from '../model.ts'
import type { HeroActionId, RunHeroModel, TrafficSparkline } from '../model.ts'
import { AnimatedNumber, Meter } from '../motion.tsx'
import { useLinks, useNav, useViewState } from '../nav.tsx'
import { Num } from '../num.tsx'
import { cn, covBarBgClass, runBtn } from '../tw.ts'
import { ConsentView } from './consent.tsx'
import { LabPanel } from './lab.tsx'

export function OverviewView() {
  const { detail } = useRun()
  // Keyed so the scope draft restarts when discovery consent turns into scope review.
  if (detail.run.status === 'waiting') return <ConsentView key={detail.run.phase + ':' + detail.run.scopeRevision} />
  return <RunOverview />
}

function Go({ to, children }: { to: ViewId; children: string }) {
  const nav = useNav()
  return <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'ml-auto')} onClick={() => nav.setView(to)}>
    {children}<Icon name="arrowR" />
  </button>
}

/** Compute the live-strip status line, surfacing login-persona auth before threat-model workers spawn. */
export function liveOverviewSummary(input: {
  phase: string
  roundNo: number
  runningWorkers: readonly { title: string }[]
  approvedPersonaIds: readonly string[]
  personas: readonly { id: string; handle: string; authKind: string }[]
  events: readonly { id: number; kind: string; detail?: Record<string, unknown> | null }[]
  hasThreatModel: boolean
}): string {
  if (input.runningWorkers.length > 0) {
    return input.runningWorkers.slice(0, 2).map(w => w.title).join(' · ')
      + (input.runningWorkers.length > 2 ? ` +${input.runningWorkers.length - 2} more` : '')
  }
  if (input.phase === 'threat_model' && !input.hasThreatModel && input.approvedPersonaIds.length > 0) {
    const approvedSet = new Set(input.approvedPersonaIds)
    const loginPersonas = input.personas.filter(p => approvedSet.has(p.id) && p.authKind === 'login')
    if (loginPersonas.length > 0) {
      const latestScopeEventId = input.events.reduce(
        (max, ev) => (ev.kind === 'scope.approved' ? Math.max(max, ev.id) : max),
        0,
      )
      const authedPersonaIds = new Set<string>()
      for (const ev of input.events) {
        if (ev.id < latestScopeEventId) continue
        if (ev.kind === 'persona.authenticated') {
          const pid = typeof ev.detail?.personaId === 'string' ? ev.detail.personaId : null
          if (pid) authedPersonaIds.add(pid)
        }
      }
      const pending = loginPersonas.filter(p => !authedPersonaIds.has(p.id))
      if (pending.length > 0) {
        return `Authenticating test accounts… (${pending.map(p => p.handle).join(', ')})`
      }
    }
  }
  return `${PHASE_LABEL[input.phase] ?? (input.phase || 'Running')} · Round ${input.roundNo ?? 0}`
}

const HERO_TONE: Record<LifecycleTone, string> = {
  accent: 'bg-accent-soft shadow-[inset_0_0_0_1px_var(--accent-line)]',
  warn: 'bg-warn-soft shadow-[inset_0_0_0_1px_var(--warn-line)]',
  danger: 'bg-danger-soft shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--danger)_35%,transparent)]',
  ok: 'bg-sunk shadow-[inset_0_0_0_1px_var(--line)]',
  neutral: 'bg-sunk shadow-[inset_0_0_0_1px_var(--line)]',
}
const HERO_ICON_TONE: Record<LifecycleTone, string> = { accent: 'text-accent', warn: 'text-warn', danger: 'text-danger', ok: 'text-ok', neutral: 'text-fg-subtle' }

/** The run's one state-aware hero: what state it is in, why, and the single next step. */
export function RunHero({ hero, onAction, busy }: { hero: RunHeroModel; onAction: (id: HeroActionId) => void; busy?: boolean }) {
  const meta = runLifecycleMeta[hero.lifecycle]
  return <section
    data-testid="run-hero"
    data-lifecycle={hero.lifecycle}
    aria-label={`Run state: ${meta.label}`}
    className={cn('mb-4 flex min-h-[52px] min-w-0 items-center gap-3 rounded-lg px-3.5 py-2.5', HERO_TONE[hero.tone])}
  >
    <span className={cn('inline-flex size-4 flex-none items-center justify-center', HERO_ICON_TONE[hero.tone])} aria-hidden="true">
      {hero.lifecycle === 'running' ? <LiveDot /> : <Icon name={meta.icon} />}
    </span>
    <div className="min-w-0 flex-1" role="status" aria-live="polite">
      <div className="num truncate text-[13.5px] font-medium leading-5 text-fg" data-slot="hero-title" title={hero.title}>{hero.title}</div>
      {hero.detail && <div className="num truncate text-[12.5px] leading-[18px] text-fg-muted" data-slot="hero-detail" title={hero.detail}>{hero.detail}</div>}
    </div>
    {hero.secondary && <button
      type="button"
      className={cn(runBtn({ variant: 'link', size: 'none' }), 'flex-none font-medium text-fg-muted hover:text-fg')}
      data-hero-action={hero.secondary.id}
      onClick={() => onAction(hero.secondary!.id)}
    >
      {hero.secondary.label}<Icon name="arrowR" />
    </button>}
    {hero.primary && <button
      type="button"
      className={cn(runBtn({ variant: 'primary' }), 'flex-none')}
      data-hero-primary=""
      data-hero-action={hero.primary.id}
      disabled={busy}
      onClick={() => onAction(hero.primary!.id)}
    >
      {hero.primary.label}
    </button>}
  </section>
}

function RunOverview() {
  const { detail, counts, events, send, pending } = useRun()
  const model = useRunModel()
  const v = useVerdict()
  const q = useDecisions()
  const nav = useNav()
  const links = useLinks()
  const r = detail.run
  const n = v.n
  const rep = model.report
  const [goalOpen, setGoalOpen] = useState(false)
  const live = r.status !== 'complete'

  const tally = SEV.map(s => [s, n[s] ?? 0] as const)
  const maxT = Math.max(1, ...tally.map(t => t[1]))
  const segT = v.conf.seg.reduce((a, s) => a + s[0], 0) || 1
  const worst = v.worst
  const goal = r.goal || ''
  const long = goal.length > 260
  const done = detail.assignments.filter(a => a.status === 'complete').length
  const runningWorkers = useMemo(() => detail.assignments.filter(a => a.status === 'running'), [detail.assignments])
  const top = useMemo(() => model.findings.filter(f => f.status !== 'dismissed').slice().sort(bySeriousness).slice(0, 7), [model])
  const cov = coverageCounts(detail.coverageEntries)
  const s = q.sections
  const needsAny = s.decide.length + s.review.length + s.follow.length > 0

  const openQueue = (sec: 'decide' | 'review' | 'follow') => {
    const first = s[sec][0] ?? s.decide[0] ?? s.review[0] ?? s.follow[0]
    if (first) nav.open('queue', { kind: 'queue', id: first.key }, { push: false })
    else nav.setView('queue')
  }

  const phases = model.workflow.phases
  const failedWorkers = detail.assignments.filter(a => a.status === 'failed')
  const failed = failedWorkers.length
  const [, setWfFilter] = useViewState('wf.filter', 'all')
  const maxP = Math.max(1, ...phases.map(p => model.workflow.byPhase.get(p)?.length ?? 0))
  const liveSummary = liveOverviewSummary({
    phase: r.phase,
    roundNo: r.roundNo,
    runningWorkers,
    approvedPersonaIds: r.approvedPersonaIds,
    personas: detail.personas,
    events,
    hasThreatModel: Boolean(detail.threatModel),
  })
  const hero = deriveRunHero({
    status: detail.activity?.lifecycle ?? r.status,
    phase: r.phase,
    roundNo: r.roundNo,
    spentUsd: r.spentUsd,
    budgetUsd: r.budgetUsd,
    spentRequests: r.spentRequests,
    budgetRequests: r.budgetRequests,
    workers: detail.assignments,
    endedAt: model.end,
    liveSummary: (runningWorkers.length > 0 ? plural(runningWorkers.length, 'active worker') + ' · ' : '') + liveSummary,
    reportLabel: rep ? `Report v${rep.version}${rep.partial ? ' (partial)' : ''} · ${fmtDate(rep.createdAt)}` : null,
    context: [runModeMeta[runModeOf(r)].label, model.scopeOrigins.length > 0 && plural(model.scopeOrigins.length, 'host')],
    fmtWhen: fmtDate,
  })
  const onHeroAction = (id: HeroActionId) => {
    if (id === 'raise_budget') openBudgetPopover()
    else if (id === 'resume') void send({ action: 'resume' }).catch(() => {})
    else if (id === 'show_failed') {
      setWfFilter('failed')
      if (failedWorkers[0]) links.worker(failedWorkers[0].id)
      else nav.setView('workflow')
    } else if (id === 'inspect') {
      if (runningWorkers[0]) links.worker(runningWorkers[0].id)
      else nav.setView('workflow')
    }
  }

  return <div className="min-h-0 flex-1 overflow-auto">
    <div className="max-w-[980px] px-6 pb-14 pt-[22px]">
      <RunHero hero={hero} onAction={onHeroAction} busy={pending > 0} />

      <h1 className="m-0 max-w-[820px] text-pretty text-[18px] font-semibold leading-[26px] tracking-[-0.017em] text-fg">{v.hed}</h1>
      {worst && <p data-ov-worst="" className="m-0 mt-1.5 flex min-w-0 items-center gap-2 text-[13px] leading-5 text-fg-muted">
        <span className="flex-none text-fg-subtle">{live ? 'Most severe so far' : 'Most serious'}</span>
        <SevGlyph sev={worst.severity} />
        <a
          className="min-w-[120px] flex-1 cursor-pointer truncate border-b border-line-strong text-fg no-underline hover:border-fg-muted"
          role="link"
          tabIndex={0}
          title={worst.title}
          onClick={() => links.finding(worst.id)}
          onKeyDown={e => { if (e.key === 'Enter') links.finding(worst.id) }}
        >
          {worst.title.replace(/\.$/, '')}
        </a>
        {worst.origin && <span className="min-w-0 max-w-[38%] shrink truncate font-mono text-[12px] text-fg-subtle" title={worst.origin}><HostLabel host={host(worst.origin)} quiet max={28} /></span>}
      </p>}
      {v.dek && <p className="m-0 mt-1 flex min-w-0 items-center gap-2 text-[13px] leading-5 text-fg-muted"><span>{v.dek}</span></p>}

      <div className="mt-[18px] grid grid-cols-[1.15fr_1fr_1fr] border-y border-line max-[1180px]:grid-cols-2">
        <div className="min-w-0 pb-3.5 pr-[18px] pt-3 max-[1180px]:col-span-full max-[1180px]:border-b max-[1180px]:border-line max-[1180px]:pr-0">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">What was asked</h3>
          <p className={cn('m-0 text-[12.5px] leading-[19px] text-fg-muted', long && !goalOpen && 'line-clamp-4')}>{goal}</p>
          {long && <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1')} onClick={() => setGoalOpen(!goalOpen)}>{goalOpen ? 'Show less' : 'Show full goal'}</button>}
        </div>
        <div className="min-w-0 border-l border-line px-[18px] pb-3.5 pt-3 max-[1180px]:border-l-0 max-[1180px]:pl-0">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">What Kovo found</h3>
          <div className="num grid grid-cols-[minmax(68px,max-content)_1fr_26px] items-center gap-x-2 gap-y-[3px] text-[12px]">
            {tally.map(([sev, k]) => [
              <span key={sev + 'l'} className={cn('flex items-center gap-1.5 whitespace-nowrap', k ? 'text-fg-muted' : 'text-fg-subtle')}><SevGlyph sev={sev} />{SEV_LABEL[sev]}</span>,
              <span key={sev + 'b'} className="block h-1 overflow-hidden rounded-[3px] bg-line">
                <TallyBar id={'ov.t.' + sev} value={k / maxT} color={SEV_COL[sev] === 'var(--fg-4)' ? 'var(--fg-3)' : SEV_COL[sev]} />
              </span>,
              <span key={sev + 'n'} className={cn('text-right', k ? 'text-fg-muted' : 'text-fg-subtle')}>{fmtN(k)}</span>,
            ])}
          </div>
        </div>
        <div className="min-w-0 border-l border-line pb-3.5 pl-[18px] pt-3">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">How confident</h3>
          <div className="mb-1.5 flex items-center gap-2 text-[15px] font-semibold tracking-[-0.01em] text-fg">{v.conf.word}</div>
          {v.conf.seg.length > 0 && <div className="mb-2 flex h-[5px] gap-0.5 overflow-hidden rounded-[4px] bg-line" title={v.conf.seg.filter(x => x[0]).map(x => x[2] + ' ' + x[0]).join(' · ')}>
            {v.conf.seg.filter(x => x[0]).map(x => <b key={x[2]} className="block h-full" style={{ flex: x[0] / segT, background: x[1] }} />)}
          </div>}
          <p className="m-0 text-[12.5px] leading-[19px] text-fg-muted">{v.conf.text}</p>
        </div>
      </div>

      <div className="num grid grid-cols-3 border-b border-line">
        <div className="min-w-0 pb-[11px] pr-3.5 pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Tokens</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <Num value={r.spentTokens} kind="tokens" />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle"><Num value={r.turnsUsed} kind="turns" compact unit="turns" /></small>
          </div>
        </div>
        <div className="min-w-0 border-l border-line px-3.5 pb-[11px] pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Workers</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <Num value={detail.assignments.length} kind="count" compact />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle">{runningWorkers.length ? `${fmtN(runningWorkers.length)} running · ` : ''}{fmtN(done)} complete{failed > 0 && <> · <span className="text-danger">{fmtN(failed)} failed</span></>}</small>
          </div>
        </div>
        <div className="min-w-0 border-l border-line pb-[11px] pl-3.5 pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Facts · evidence</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <Num value={detail.facts.length} kind="count" compact />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle">· {fmtN(detail.evidence.length)}</small>
          </div>
        </div>
      </div>

      <div className="mt-1.5 grid grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] gap-x-7 max-[1180px]:grid-cols-1">
        <div>
          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Needs you<Go to="queue">Open queue</Go>
            </h4>
            {needsAny
              ? <div className="grid grid-cols-3 overflow-hidden rounded-lg border border-line">
                {([['decide', 'Decide', 'To approve or deny'], ['review', 'Review', 'Unverified findings'], ['follow', 'Follow up', 'Flagged coverage']] as const).map(([k, l, sub], idx) => {
                  const hot = k === 'decide' && s.decide.length > 0
                  return <button
                    key={k}
                    type="button"
                    className={cn(
                      'flex h-auto cursor-pointer flex-col items-start gap-px whitespace-normal rounded-none border-0 bg-transparent px-3 py-[9px] text-left font-sans shadow-none transition-colors duration-[var(--d1)] hover:bg-hover',
                      idx > 0 && 'border-l border-line',
                    )}
                    onClick={() => openQueue(k)}
                  >
                    <span className={cn('num flex items-center gap-[7px] text-[15px] font-medium leading-[22px]', hot ? 'text-warn' : 'text-fg')}>
                      {hot && <StatusGlyph status="paused" />}
                      <AnimatedNumber id={'ov.q.' + k} value={s[k].length} />
                      <span className="text-[12.5px] font-medium text-fg-muted">{l}</span>
                    </span>
                    <span className="text-[11.5px] font-normal text-fg-subtle">{sub}</span>
                  </button>
                })}
              </div>
              : <div className="flex items-center gap-2.5 rounded-lg border border-line px-3 py-2.5 text-[12.5px] text-fg-muted">
                <StatusGlyph status="complete" />{model.findings.length ? 'Nothing needs you. Every finding is decided or verified.' : 'Nothing needs you.'}
              </div>}
          </div>

          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Most serious findings
              {model.findings.length > 0 && <span className="num font-normal text-fg-subtle">{fmtN(top.length)} of {fmtN(model.findings.length)}</span>}
              <Go to="findings">All findings</Go>
            </h4>
            <div className="border-t border-line">
              {top.map(f => <div
                key={f.id}
                className="flex h-[34px] cursor-pointer items-center gap-2.5 border-b border-line pl-0.5 pr-1 transition-colors duration-[var(--d1)] hover:bg-hover"
                role="button"
                tabIndex={0}
                onClick={() => links.finding(f.id)}
                onKeyDown={e => { if (e.key === 'Enter') links.finding(f.id) }}
              >
                <span className="inline-flex size-3.5 flex-none items-center justify-center"><SevGlyph sev={f.severity} /></span>
                <span className="inline-flex size-3.5 flex-none items-center justify-center" title={stLabel(normFStatus(f.status))}><StatusGlyph status={normFStatus(f.status)} /></span>
                <span className="min-w-0 flex-1 truncate text-fg" title={f.title || undefined}><FindingTitle title={f.title} /></span>
                <span className="w-[130px] flex-none truncate text-right font-mono text-[12px] text-fg-subtle max-[1180px]:hidden">
                  <HostLabel host={host(f.origin)} quiet max={22} />
                </span>
              </div>)}
              {!top.length && <p className="my-2 text-[12.5px] text-fg-subtle">{live ? 'No findings drafted yet.' : 'No findings.'}</p>}
            </div>
          </div>
        </div>

        <div>
          <LabPanel />
          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Workflow
              <span className="num font-normal text-fg-subtle">{fmtN(detail.assignments.length)} workers</span>
              <Go to="workflow">Graph</Go>
            </h4>
            <div
              data-ov-workflow=""
              className="cursor-pointer rounded-lg border border-line px-2.5 py-1 transition-colors duration-[var(--d1)] hover:border-line-strong"
              role="button"
              tabIndex={0}
              title="Open the workflow graph"
              onClick={() => nav.setView('workflow')}
              onKeyDown={e => { if (e.key === 'Enter') nav.setView('workflow') }}
            >
              {phases.map(p => {
                const ws = model.workflow.byPhase.get(p) ?? []
                if (!ws.length && p === 'retest') return null
                const dn = ws.filter(a => a.status === 'complete').length
                const pz = ws.filter(a => a.status === 'paused' || a.status === 'waiting_approval').length
                const run = ws.filter(a => a.status === 'running').length
                const fl = ws.filter(a => a.status === 'failed').length
                return <div key={p} data-ov-phase={p} className={cn('grid h-6 items-center gap-2 text-[12px]', WF_SUMMARY_COLS)}>
                  <span className="min-w-0 truncate text-fg-muted">{PHASE_LABEL[p] ?? p}</span>
                  <span className="relative h-1 overflow-hidden rounded-[2px] bg-line">
                    <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-fg-subtle" style={{ width: `${ws.length / maxP * 100}%` }} />
                    {pz > 0 && <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-warn" style={{ width: `${pz / maxP * 100}%` }} />}
                  </span>
                  <span className="num min-w-[7ch] whitespace-nowrap text-right font-medium text-fg">{fmtN(ws.length)}</span>
                  <PhaseStatusWord total={ws.length} done={dn} paused={pz} running={run} failed={fl} />
                </div>
              })}
              {rep && <div className={cn('grid h-6 items-center gap-2 text-[12px]', WF_SUMMARY_COLS)}>
                <span className="min-w-0 truncate text-fg-muted">Report</span>
                <span className="relative h-1 overflow-hidden rounded-[2px] bg-line">
                  <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-fg" style={{ width: '4%' }} />
                </span>
                <span className="num min-w-[7ch] whitespace-nowrap text-right font-medium text-fg">v{rep.version}</span>
                <span className="whitespace-nowrap text-[11.5px] text-fg-subtle">{rep.partial ? 'partial' : 'ready'}</span>
              </div>}
            </div>
          </div>

          <div className="pt-4">
            <TrafficPanel exchanges={counts.exchanges} />
          </div>

          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Coverage
              <span className="num font-normal text-fg-subtle">{fmtN(detail.coverageEntries.length)} cells</span>
              <Go to="surface">Surface</Go>
            </h4>
            {cov.length
              ? <>
                <div className="mb-2 mt-0.5 flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full">
                  {cov.map(c => <i key={c.status} className={cn('block h-full', covBarBgClass(c.status))} style={{ flex: c.count }} title={`${c.label} ${c.count}`} />)}
                </div>
                <div className="num flex flex-wrap gap-x-3.5 gap-y-1.5 text-[12px] text-fg-muted">
                  {cov.map(c => <span key={c.status} className="inline-flex items-center gap-1.5">
                    <CovSwatch status={c.status} size={[14, 11]} />{c.label} <span className="text-fg-subtle">{c.count}</span>
                  </span>)}
                </div>
              </>
              : <p className="m-0 text-[12.5px] text-fg-subtle">No coverage recorded yet.</p>}
          </div>
        </div>
      </div>
    </div>
  </div>
}

/** Traffic: requests/min sparkline with the per-origin cap line, denied ticks and a hover readout. */
function TrafficPanel({ exchanges }: { exchanges: number }) {
  const { detail, events } = useRun()
  const r = detail.run
  const live = runLifecycleMeta[runLifecycleOf(detail.activity?.lifecycle ?? r.status)].live
  const [win, setWin] = useViewState<'auto' | 'full'>('ov.trafficWindow', 'auto')
  const model = useRunModel()
  // Wall-clock "now" only after mount: SSR and the hydrating render share the run's own end time,
  // so the live window's axis and buckets never mismatch between server and client.
  const [clock, setClock] = useState<number | null>(null)
  useEffect(() => {
    if (!live) return
    setClock(Date.now())
    const id = window.setInterval(() => setClock(Date.now()), 30_000)
    return () => window.clearInterval(id)
  }, [live])
  const now = clock ?? model.end
  const spark = useMemo(() => buildTrafficSparkline({
    status: detail.activity?.lifecycle ?? r.status,
    createdAt: r.createdAt,
    now,
    maxRpsPerOrigin: r.maxRpsPerOrigin,
    exchanges: detail.exchangesSummary,
    events,
    window: live && win === 'full' ? 'full' : undefined,
  }), [detail, r, events, now, live, win])
  const winBtn = (on: boolean) => cn(runBtn({ variant: on ? 'ghostOn' : 'ghost', size: 'xs' }), 'h-5 px-1.5 text-[11px]')
  return <>
    <h4 className="m-0 mb-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] font-medium text-fg-muted">
      Traffic
      <span className="num whitespace-nowrap font-normal text-fg-subtle"><Num value={exchanges} kind="count" compact unit={exchanges === 1 ? 'exchange' : 'exchanges'} /></span>
      {live && !spark.empty && <span className="inline-flex flex-none items-center gap-0.5" role="group" aria-label="Traffic window">
        <button type="button" className={winBtn(win !== 'full')} aria-pressed={win !== 'full'} onClick={() => setWin('auto')}>Last 60 min</button>
        <button type="button" className={winBtn(win === 'full')} aria-pressed={win === 'full'} onClick={() => setWin('full')}>Full run</button>
      </span>}
      <Go to="exchanges">Exchanges</Go>
    </h4>
    {spark.empty && exchanges === 0
      ? <p data-ov-traffic-empty="" className="m-0 text-[12.5px] text-fg-subtle">No traffic recorded.</p>
      : <TrafficSparklineChart spark={spark} />}
    {spark.quiet && <p data-testid="traffic-quiet" className="num m-0 mt-1.5 flex items-center gap-1.5 text-[12px] text-warn">
      <Icon name="alert" size={12} />No traffic in the last 10 min{spark.lastAt != null ? ` · last request ${fmtTime(spark.lastAt)}` : ''}
    </p>}
  </>
}

/** Requests/min with one decimal below 10 (long full-run buckets average to fractions). */
const fmtRate = (v: number) => (v >= 10 || Number.isInteger(v) ? fmtN(Math.round(v)) : v.toFixed(1))

/** SVG sparkline; the readout is tabular and follows the pointer (or ←/→ when focused). */
export function TrafficSparklineChart({ spark }: { spark: TrafficSparkline }) {
  const [hover, setHover] = useState<number | null>(null)
  const n = spark.buckets.length
  const H = 40
  const y = (v: number) => H - Math.min(1, v / spark.yMax) * (H - 2)
  const line = spark.buckets.map((b, i) => `${i === 0 ? 'M' : 'L'}${(i + 0.5).toFixed(2)},${y(b.perMin).toFixed(2)}`).join(' ')
  const area = `M0.5,${H} ${line.replace(/^M/, 'L')} L${(n - 0.5).toFixed(2)},${H} Z`
  const capY = spark.capInScale ? y(spark.capPerMin) : null
  const axisFmt = spark.t1 - spark.t0 > 86_400_000 ? fmtDate : fmtTime
  const pick = (e: ReactPointerEvent<HTMLDivElement>) => {
    const box = e.currentTarget.getBoundingClientRect()
    if (box.width <= 0) return
    setHover(Math.max(0, Math.min(n - 1, Math.floor((e.clientX - box.left) / box.width * n))))
  }
  const key = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return
    e.preventDefault()
    setHover(h => Math.max(0, Math.min(n - 1, (h ?? n - 1) + (e.key === 'ArrowLeft' ? -1 : 1))))
  }
  const b = hover != null ? spark.buckets[hover] : null
  const winLabel = spark.window === 'live' ? 'last 60 min' : 'full run'
  return <div data-testid="traffic-sparkline" data-window={spark.window}>
    <div
      className="relative h-11 cursor-crosshair border-b border-line outline-none focus-visible:shadow-[0_0_0_2px_var(--accent-line)]"
      tabIndex={0}
      role="img"
      aria-label={`Requests per minute, ${winLabel}: peak ${fmtRate(spark.peakPerMin)} req/min, ${fmtN(spark.denied)} denied or error responses`}
      onPointerMove={pick}
      onPointerLeave={() => setHover(null)}
      onKeyDown={key}
      onBlur={() => setHover(null)}
    >
      <svg className="absolute inset-0 size-full overflow-visible" viewBox={`0 0 ${n} ${H}`} preserveAspectRatio="none" aria-hidden="true">
        <path d={area} className="fill-[var(--accent-soft)]" />
        <path d={line} fill="none" className="stroke-[var(--accent)]" strokeWidth={1.5} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        {capY != null && <line data-testid="traffic-cap-line" x1={0} x2={n} y1={capY} y2={capY} className="stroke-[var(--fg-3)]" strokeWidth={1} strokeDasharray="4 3" vectorEffect="non-scaling-stroke" />}
        {spark.buckets.map((bk, i) => bk.denied > 0 && <rect key={i} data-traffic-denied="" x={i + 0.15} y={H - 6} width={0.7} height={6} className="fill-[var(--danger)]" />)}
        {hover != null && <line x1={hover + 0.5} x2={hover + 0.5} y1={0} y2={H} className="stroke-[var(--fg-3)]" strokeWidth={1} vectorEffect="non-scaling-stroke" />}
      </svg>
      {spark.capPerMin > 0 && <span
        className="num pointer-events-none absolute right-0 rounded-[3px] bg-panel/90 px-1 text-[10.5px] leading-[13px] text-fg-subtle"
        style={{ top: capY != null ? `max(0px, calc(${(capY / H * 100).toFixed(1)}% - 14px))` : 0 }}
        data-testid="traffic-cap-label"
      >
        Cap <Num value={spark.capPerMin} kind="count" compact />/min{capY == null ? ' · off scale' : ''}
      </span>}
    </div>
    <div data-ov-traffic-axis="" className="num mt-[3px] flex justify-between gap-2 whitespace-nowrap text-[11px] text-fg-subtle">
      <span>{axisFmt(spark.t0)}</span>
      <span>{axisFmt(spark.t0 + (spark.t1 - spark.t0) / 2)}</span>
      <span>{spark.window === 'live' ? 'now' : axisFmt(spark.t1)}</span>
    </div>
    <div className="num mt-1 flex min-h-4 items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-muted" data-testid="traffic-readout" aria-live="off">
      {b
        ? <>
          <span className="text-fg-subtle">{axisFmt(b.t)}</span>
          <span className="text-fg-faint">·</span>
          <span className="text-fg tabular-nums">{fmtRate(b.perMin)} req/min</span>
          <span className="text-fg-faint">·</span>
          <Num value={b.count} kind="count" unit="req" />
          <span className="text-fg-faint">·</span>
          <span className={b.denied > 0 ? 'text-danger' : 'text-fg-subtle'}><Num value={b.denied} kind="count" unit="denied" /></span>
        </>
        : <>
          <span className="text-fg-subtle">Peak</span>
          <span className="text-fg tabular-nums">{fmtRate(spark.peakPerMin)} req/min</span>
          <span className="text-fg-faint">·</span>
          <span className={spark.denied > 0 ? 'text-danger' : 'text-fg-subtle'}><Num value={spark.denied} kind="count" compact unit="denied" /></span>
          <span className="text-fg-faint">·</span>
          <span className="text-fg-subtle">{winLabel}</span>
        </>}
    </div>
  </div>
}

/** Workflow summary row columns: label / bar (never below 36px) / count / status word. */
const WF_SUMMARY_COLS = 'grid-cols-[minmax(64px,104px)_minmax(36px,1fr)_auto_minmax(44px,auto)]'

/** Phase status word listing every live state ("5 running · 1 paused"), failures in danger. */
function PhaseStatusWord({ total, done, paused, running, failed }: { total: number; done: number; paused: number; running: number; failed: number }) {
  const parts = [
    running > 0 && <span key="r">{fmtN(running)} running</span>,
    paused > 0 && <span key="p">{fmtN(paused)} paused</span>,
    failed > 0 && <span key="f" className="text-danger">{fmtN(failed)} failed</span>,
  ].filter(Boolean)
  const fallback = !total ? '—' : done === total ? 'done' : `${fmtN(done)} done`
  return <span className="num min-w-0 truncate whitespace-nowrap text-[11.5px] text-fg-subtle">
    {parts.length ? parts.flatMap((x, i) => i ? [<span key={'s' + i}> · </span>, x] : [x]) : fallback}
  </span>
}

/** Tally bar that grows from its previous value (keyed per severity so it animates on run switch). */
function TallyBar({ id, value, color }: { id: string; value: number; color: string }) {
  return <Meter id={id} value={value} warn={false} wide className="block h-full rounded-[3px] bg-transparent" barColor={color} />
}
