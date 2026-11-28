import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createProject, syncGithubRepositories, workspaceData } from '../actions.ts'
import { FormError, useAction } from '../components/common.tsx'
import {
  CreateProjectGithubBlock,
  type GithubPatStatusSummary,
} from '../components/project/CreateProjectGithubBlock.tsx'
import { fmtN, host, plural } from '../components/run/format.ts'
import { StatusGlyph } from '../components/run/glyphs.tsx'
import { Icon } from '../components/run/icons.tsx'
import { PHASE_LABEL, runStatusLabel } from '../components/run/meta.ts'
import {
  formatFullDateTime,
  formatRelativeTime,
  middleTruncate,
  projectDisambiguators,
  useNow,
  useShell,
} from '../components/shell/AppShell.tsx'
import { Badge } from '../components/ui/badge.tsx'
import { Button, buttonVariants } from '../components/ui/button.tsx'
import { Card } from '../components/ui/card.tsx'
import { Checkbox } from '../components/ui/checkbox.tsx'
import { Dialog, DialogContent, DialogTitle } from '../components/ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../components/ui/disclosure.tsx'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../components/ui/dropdown-menu.tsx'
import { EmptyState } from '../components/ui/empty-state.tsx'
import { Input, NativeSelect, Textarea } from '../components/ui/input.tsx'
import { HintTooltip } from '../components/ui/tooltip.tsx'
import type { RunStatus } from '../domain.ts'
import { cn } from '../lib/cn.ts'
import { isCanonicalRunStatus, isTerminalRunStatus } from '../server/run-status.ts'

type HomeSearch = { new?: string }

export const Route = createFileRoute('/')({
  validateSearch: (search: Record<string, unknown>): HomeSearch => ({
    // TanStack's default parseSearch JSON-decodes `?new=1` into the number 1.
    new: search.new === 1 || search.new === '1' || search.new === true ? '1' : undefined,
  }),
  loader: () => workspaceData(),
  component: Workspace,
})

function CreateProjectSheet({
  isModal,
  open = true,
  canCancel,
  githubPatStatus,
  onClose,
}: {
  isModal: boolean
  open?: boolean
  canCancel: boolean
  githubPatStatus: GithubPatStatusSummary
  onClose: () => void
}) {
  const navigate = useNavigate()
  const [environment, setEnvironment] = useState<'public' | 'local-lab'>('public')
  const [includeSubdomains, setIncludeSubdomains] = useState(true)
  const [selectedRepos, setSelectedRepos] = useState<string[]>([])
  const [submitStatus, setSubmitStatus] = useState('')
  const action = useAction()

  useEffect(() => {
    if (!isModal || open) return
    setEnvironment('public')
    setIncludeSubdomains(true)
    setSelectedRepos([])
    setSubmitStatus('')
  }, [isModal, open])

  const formContent = (
    <form
      className={cn(isModal && 'flex min-h-0 flex-1 flex-col overflow-hidden')}
      onSubmit={event => {
        event.preventDefault()
        const form = new FormData(event.currentTarget)
        const nextEnv = environment
        const reposToSync = selectedRepos.slice(0, 20)
        setSubmitStatus('Creating project…')
        void action.submit(async () => {
          const project = await createProject({ data: {
            requestId: crypto.randomUUID(),
            name: String(form.get('name')),
            seeds: String(form.get('seeds')).split(/[\s,]+/).filter(Boolean),
            environment: nextEnv,
            includeSubdomains: nextEnv === 'public' ? includeSubdomains : false,
          } })
          let syncError: string | undefined
          if (reposToSync.length > 0) {
            setSubmitStatus(`Syncing ${reposToSync.length} ${reposToSync.length === 1 ? 'repo' : 'repos'}…`)
            try {
              await syncGithubRepositories({ data: { projectId: project.id, repos: reposToSync } })
            } catch (err) {
              // Non-blocking: still open the newly created project cleanly and surface a retryable error banner.
              syncError = err instanceof Error ? err.message : 'Initial GitHub repository sync failed.'
            }
          }
          return { project, syncError }
        }, async ({ project, syncError }) => {
          setSubmitStatus('')
          setEnvironment('public')
          setIncludeSubdomains(true)
          setSelectedRepos([])
          onClose()
          await navigate({
            to: '/projects/$projectId',
            params: { projectId: project.id },
            search: syncError ? { syncError: syncError.slice(0, 300) } : {},
          })
        }).finally(() => setSubmitStatus(''))
      }}
    >
      {/* Inline onboarding already has a "Start your first project" title; only the modal needs a header row. */}
      {isModal && (
        <div className="flex flex-none items-center gap-2.5 border-b border-line px-4 py-[11px] font-medium text-fg">
          <Icon name="plus" />
          <DialogTitle className="text-[13px] font-medium tracking-normal text-fg">New project</DialogTitle>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ml-auto text-fg-subtle hover:text-fg"
            disabled={action.pending}
            onClick={onClose}
            aria-label="Close modal"
          >
            <Icon name="close" />
          </Button>
        </div>
      )}

      <div
        className={cn(
          'flex flex-col gap-4 px-5 py-[18px] max-[720px]:px-4',
          isModal && 'min-h-0 flex-1 overflow-y-auto',
        )}
      >
        <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
          <span>Project name</span>
          <Input name="name" placeholder="Acme Web" required maxLength={160} autoFocus={isModal} />
        </label>

        <div className="grid gap-[9px]">
          <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
            <span>Sites</span>
            <Textarea
              className="w-full"
              name="seeds"
              rows={2}
              placeholder={'https://app.example.com'}
              required
            />
          </label>

          <label
            className={cn(
              'flex select-none flex-wrap items-center gap-x-2 gap-y-1 text-[12.5px] font-[450] text-fg-muted',
              environment !== 'public' ? 'cursor-default opacity-50' : 'cursor-pointer',
            )}
          >
            <Checkbox
              name="includeSubdomains"
              checked={environment === 'public' ? includeSubdomains : false}
              disabled={environment !== 'public' || action.pending}
              aria-label="Include subdomains"
              onCheckedChange={checked => setIncludeSubdomains(Boolean(checked))}
            />
            {/* No min-w-0: the longest word sets the floor, so the *.domain chip wraps instead of overlapping. */}
            <span className="flex-[1_1_0] whitespace-normal sm:flex-none" data-slot="include-subdomains-text">Include subdomains</span>
            <code className="rounded-[5px] border border-line-2 bg-sunk px-1.5 py-px font-mono text-[11px] text-fg-subtle">
              *.domain
            </code>
          </label>
        </div>

        <CreateProjectGithubBlock
          initialPatStatus={githubPatStatus}
          selectedRepos={selectedRepos}
          onChangeSelectedRepos={setSelectedRepos}
          disabled={action.pending}
        />

        <Disclosure className="border-t border-line pt-2.5">
          <DisclosureTrigger className="h-auto w-auto max-w-full whitespace-normal rounded-sm bg-transparent px-0 py-0.5 text-[12px] font-medium text-fg-subtle shadow-none hover:bg-transparent hover:text-fg-muted">
            <span>Advanced configuration</span>
            {environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
          </DisclosureTrigger>
          <DisclosureContent className="mt-2.5 grid gap-2.5 rounded-lg border border-line bg-sunk px-3 py-[11px]">
            <label className="grid gap-1.5 text-[12.5px] font-medium text-fg">
              <span>Target environment</span>
              <NativeSelect
                name="environment"
                value={environment}
                onChange={e => {
                  const next = e.target.value === 'local-lab' ? 'local-lab' : 'public'
                  setEnvironment(next)
                  if (next !== 'public') setIncludeSubdomains(false)
                  else setIncludeSubdomains(true)
                }}
              >
                <option value="public">Public website</option>
                <option value="local-lab">Local lab (localhost / private staging)</option>
              </NativeSelect>
            </label>
          </DisclosureContent>
        </Disclosure>

        <FormError error={action.error} />
      </div>

      <div className="flex flex-none items-center justify-end gap-2 border-t border-line bg-sunk px-4 py-2.5">
        {submitStatus && <span className="mr-auto text-[12px] text-fg-subtle">{submitStatus}</span>}
        {canCancel && (
          <Button type="button" variant="outline" disabled={action.pending} onClick={onClose}>
            Cancel
          </Button>
        )}
        <Button type="submit" variant="default" disabled={action.pending}>
          {submitStatus || (selectedRepos.length > 0 ? `Create & sync (${selectedRepos.length})` : 'Create project')}
        </Button>
      </div>
    </form>
  )

  if (!isModal) {
    return (
      <Card className="overflow-hidden border-line bg-panel">
        {formContent}
      </Card>
    )
  }

  return (
    <Dialog
      open={open}
      closeOnEscape={!action.pending}
      onOpenChange={(nextOpen, details) => {
        if (!nextOpen) {
          if (action.pending) {
            details.cancel()
            return
          }
          onClose()
        }
      }}
    >
      <DialogContent
        aria-label="New project"
        className="flex max-h-[calc(100vh-56px)] max-w-[540px] flex-col overflow-hidden rounded-2xl border-line-2 bg-panel p-0 [&_svg]:block [&_svg]:flex-none"
      >
        {formContent}
      </DialogContent>
    </Dialog>
  )
}

/** Canonical statuses whose label (not the last phase) describes the run, so table and rail agree. */
const STATUS_LABELLED_RUN_STATES: ReadonlySet<RunStatus> = new Set<RunStatus>(['failed', 'paused', 'budget_paused', 'stopped'])

function formatRunPhase(status: string, phase: string): string {
  if (status === 'complete') return 'Complete'
  if (isCanonicalRunStatus(status) && STATUS_LABELLED_RUN_STATES.has(status)) return runStatusLabel(status)
  // Legacy terminal aliases (e.g. a cancelled run) never read as their last phase either.
  if (!isCanonicalRunStatus(status) && isTerminalRunStatus(status)) return runStatusLabel(status)
  return PHASE_LABEL[phase] ?? runStatusLabel(status)
}

/**
 * Split a trailing distinguishing qualifier (e.g. "seed 100004") off a project
 * name so truncation eats the shared prefix first and the suffix stays visible.
 */
function splitProjectNameQualifier(name: string): { base: string; qualifier: string } {
  // Lazy base so "… seed 100004" keeps the whole "seed 100004" qualifier, not just the digits.
  const match = /^(.*?\S)\s+(seed\s+\d+.*|#?\d[\w.-]*)$/i.exec(name)
  if (!match || !match[1] || !match[2]) return { base: name, qualifier: '' }
  return { base: match[1], qualifier: match[2] }
}

/** Seed-host cell copy: never a "none" dash followed by "+N more". */
function summarizeSeedHosts(seedHosts: readonly string[], hostCount: number): {
  summary: string
  extra: number
} {
  if (seedHosts.length === 0) {
    return { summary: hostCount > 0 ? plural(hostCount, 'host') : '—', extra: 0 }
  }
  return {
    summary: seedHosts.slice(0, 2).join(', '),
    extra: Math.max(0, hostCount - Math.min(2, seedHosts.length)),
  }
}

/** Header count: "12 of 28" while a filter is active. */
function formatProjectCount(filter: string, visible: number, total: number): string {
  return filter.trim() ? `${fmtN(visible)} of ${fmtN(total)}` : fmtN(total)
}

const BANNER_ROW_CLASS =
  'flex min-h-10 flex-none flex-wrap items-center gap-x-2.5 gap-y-2 border-b border-warn-line bg-warn-soft py-2 pl-[18px] pr-3.5 text-[12.5px] text-fg-muted max-[720px]:items-start'

function ModelPoolBanner({ title, body, cta }: { title: string; body: string; cta: string }) {
  return (
    <div className={BANNER_ROW_CLASS} role="status" data-slot="model-pool-banner">
      <Icon name="alert" className="flex-none text-warn max-[720px]:mt-0.5" />
      <span className="min-w-0 grow basis-[min(100%,320px)]" data-slot="model-pool-banner-copy">
        <b className="font-medium text-fg">{title}</b> {body}
      </span>
      <Link className={cn(buttonVariants({ variant: 'outline' }), 'ml-auto flex-none')} to="/settings" search={{}}>
        {cta}
        <Icon name="arrowR" />
      </Link>
    </div>
  )
}

// Trailing 72px column holds the persistent quiet row actions (never an overlay on the metrics).
const PROJECT_GRID_COLS =
  'grid-cols-[minmax(200px,1.45fr)_minmax(160px,1.15fr)_minmax(170px,1fr)_150px_72px] max-[960px]:grid-cols-[minmax(170px,1.3fr)_minmax(130px,1fr)_140px_72px] max-[720px]:grid-cols-[minmax(0,1fr)_auto]'

type WorkspaceProject = Awaited<ReturnType<typeof workspaceData>>['projects'][number]

function ProjectNameLink({ project, disambiguator }: { project: WorkspaceProject; disambiguator?: string }) {
  const { base, qualifier } = splitProjectNameQualifier(project.name)
  return (
    <Link
      to="/projects/$projectId"
      params={{ projectId: project.id }}
      className="flex min-w-0 items-baseline gap-1 font-medium text-fg decoration-line-strong underline-offset-2 hover:underline group-data-[active]/row:focus-visible:outline-none"
      title={[project.name, disambiguator].filter(Boolean).join(' — ')}
      data-slot="project-name-link"
    >
      <span className="min-w-[2ch] truncate">{base}</span>
      {qualifier && (
        <span className="max-w-[60%] flex-none truncate tabular-nums text-fg-subtle max-[720px]:max-w-full" data-slot="project-name-qualifier">
          {qualifier}
        </span>
      )}
      {/* Namesakes: a quiet host / short-id suffix, middle-truncated so its distinguishing tail survives. */}
      {disambiguator && (
        <span className="ml-1 max-w-full flex-none truncate font-mono text-[11.5px] font-normal text-fg-subtle" data-slot="project-name-disambiguator">
          {middleTruncate(disambiguator, 32)}
        </span>
      )}
    </Link>
  )
}

const ROW_ACTION_BTN = cn(buttonVariants({ variant: 'ghost', size: 'icon' }), 'size-[26px] text-fg-subtle hover:text-fg')

/** Persistent quiet actions: present at 45% opacity, full on row hover / focus / keyboard-active, no movement. */
function ProjectRowActions({ project }: { project: WorkspaceProject }) {
  const navigate = useNavigate()
  const latest = project.latestRun
  return (
    <div
      data-slot="project-row-actions"
      className="flex items-center justify-end gap-1 opacity-45 transition-[opacity,translate] duration-[var(--d1)] ease-kovo group-hover/row:opacity-100 group-focus-within/row:opacity-100 group-data-[active]/row:opacity-100 max-[720px]:hidden"
    >
      <HintTooltip label="New run" shortcut="R">
        <Link
          to="/projects/$projectId"
          params={{ projectId: project.id }}
          search={{ newRun: '1' }}
          className={ROW_ACTION_BTN}
          aria-label={`New run for ${project.name}`}
          data-slot="project-row-new-run"
        >
          <Icon name="play" />
        </Link>
      </HintTooltip>
      <DropdownMenu>
        <HintTooltip label="More actions">
          <DropdownMenuTrigger className={ROW_ACTION_BTN} aria-label={`More actions for ${project.name}`}>
            <Icon name="dots" />
          </DropdownMenuTrigger>
        </HintTooltip>
        <DropdownMenuContent>
          <DropdownMenuItem onClick={() => void navigate({ to: '/projects/$projectId', params: { projectId: project.id } })}>
            Open project
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => void navigate({ to: '/projects/$projectId', params: { projectId: project.id }, search: { newRun: '1' } })}>
            New run
          </DropdownMenuItem>
          {latest && (
            <DropdownMenuItem onClick={() => void navigate({ to: '/runs/$runId', params: { runId: latest.id }, search: {} })}>
              Open latest run
            </DropdownMenuItem>
          )}
          <DropdownMenuItem onClick={() => void navigate({ to: '/projects/$projectId', params: { projectId: project.id }, search: { tab: 'runs' } })}>
            All runs
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}

function ProjectLatestRunCell({ latest, now }: { latest: NonNullable<WorkspaceProject['latestRun']>; now: number }) {
  const relTime = formatRelativeTime(latest.startedAt, { compact: false, now })
  const fullTime = formatFullDateTime(latest.startedAt)
  return (
    <Link
      to="/runs/$runId"
      params={{ runId: latest.id }}
      search={{}}
      className="inline-flex max-w-full min-w-0 items-center gap-[7px] text-fg-muted hover:text-fg"
      title={`${latest.goal} (${fullTime})`}
    >
      <span className="inline-flex size-3.5 flex-none items-center justify-center">
        <StatusGlyph status={latest.status} />
      </span>
      <span className="truncate" data-slot="latest-run-label">{formatRunPhase(latest.status, latest.phase)}</span>
      <time
        className="flex-none whitespace-nowrap text-[11.5px] tabular-nums text-fg-subtle"
        dateTime={new Date(latest.startedAt).toISOString()}
        title={fullTime}
        suppressHydrationWarning
      >
        {relTime}
      </time>
    </Link>
  )
}

function ProjectRow({ project, now, active, disambiguator, onOpen, onFocusRow }: {
  project: WorkspaceProject
  now: number
  active: boolean
  disambiguator?: string
  onOpen: () => void
  onFocusRow: () => void
}) {
  const seedHosts = project.seeds.map(host)
  const { summary: hostSummary, extra: extraHosts } = summarizeSeedHosts(seedHosts, project.hostCount)
  const latest = project.latestRun
  return (
    <div
      data-slot="project-row"
      data-active={active ? '' : undefined}
      // Highlights are instant (no transition): j/k and the pointer move them many times a session.
      className={cn(
        'group/row relative grid min-h-11 scroll-mt-8 cursor-pointer items-center gap-3 border-b border-line px-[18px] py-1.5 hover:bg-hover',
        'data-[active]:bg-hover data-[active]:shadow-[inset_2px_0_0_var(--accent)]',
        PROJECT_GRID_COLS,
      )}
      onFocus={onFocusRow}
      onClick={e => {
        // Portalled menu items bubble through React but are not DOM children of the row.
        if (!e.currentTarget.contains(e.target as Node)) return
        if ((e.target as HTMLElement).closest('a, button')) return
        onOpen()
      }}
    >
      <div className="flex min-w-0 items-center gap-2">
        <ProjectNameLink project={project} disambiguator={disambiguator} />
        {project.environment === 'local-lab' && <Badge variant="warn">Local Lab</Badge>}
      </div>

      <div
        className="flex min-w-0 items-center gap-1.5 text-fg-muted max-[960px]:hidden"
        title={seedHosts.join(', ') || undefined}
        data-slot="seed-host-cell"
      >
        <span className={cn('min-w-0 truncate text-[12px]', seedHosts.length > 0 && 'font-mono')}>{hostSummary}</span>
        {extraHosts > 0 && <Badge className="bg-sunk tabular-nums">+{fmtN(extraHosts)}</Badge>}
      </div>

      <div className="flex min-w-0 items-center gap-[7px] text-[12.5px] text-fg-muted max-[720px]:hidden">
        {latest ? <ProjectLatestRunCell latest={latest} now={now} /> : <span className="text-fg-subtle">No runs yet</span>}
      </div>

      <div className="flex items-center justify-end gap-2 whitespace-nowrap text-[12px] tabular-nums text-fg-muted" data-slot="project-row-metrics">
        <span className={project.runCount > 0 ? '' : 'text-fg-subtle'}>
          {plural(project.runCount, 'run')}
        </span>
        <span className="text-fg-subtle max-[720px]:hidden">·</span>
        <span className={cn(latest && latest.confirmedCount > 0 ? 'font-medium text-fg' : 'text-fg-subtle', 'max-[720px]:hidden')}>
          {latest ? `${fmtN(latest.confirmedCount)} confirmed` : '—'}
        </span>
      </div>

      <ProjectRowActions project={project} />
    </div>
  )
}

/** Window-level keys must never act while the user types or an overlay owns the keyboard. */
function rowNavBlocked(e: KeyboardEvent): boolean {
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || e.shiftKey) return true
  const target = e.target
  if (target instanceof HTMLElement) {
    if (target.isContentEditable || target.closest('input, textarea, select, [contenteditable="true"]')) return true
  }
  return Boolean(document.querySelector('[role="dialog"], [role="alertdialog"], [data-slot="dialog-content"], [role="menu"]'))
}

/** Next active row for j/k (always) and ↑/↓ (once row navigation is engaged); null = not a nav key. */
function rowNavStep(key: string, active: number, count: number): number | null {
  if (count === 0) return null
  const engaged = active >= 0
  if (key === 'j' || (engaged && key === 'ArrowDown')) return engaged ? Math.min(count - 1, active + 1) : 0
  if (key === 'k' || (engaged && key === 'ArrowUp')) return engaged ? Math.max(0, active - 1) : 0
  return null
}

/** AppShell's G-chord window: keys right after `g` belong to the chord, not the table. */
const G_CHORD_MS = 800

/**
 * Roving active row for the projects table: j/k (and ↑/↓ once engaged) move
 * it instantly, Enter opens the project, R opens New run. The active row's
 * name link takes focus so screen readers follow and Enter stays native.
 */
function useProjectRowNav(rows: readonly WorkspaceProject[], onOpen: (p: WorkspaceProject) => void, onNewRun: (p: WorkspaceProject) => void) {
  const [active, setActive] = useState(-1)
  const listRef = useRef<HTMLDivElement>(null)
  const keyboardMoveRef = useRef(false)
  const activeRef = useRef(active)
  activeRef.current = active

  useEffect(() => {
    let lastG = Number.NEGATIVE_INFINITY
    const onKeyDown = (e: KeyboardEvent) => {
      if (rowNavBlocked(e)) return
      if (e.key === 'g') { lastG = e.timeStamp; return }
      if (e.timeStamp - lastG < G_CHORD_MS) return
      const current = activeRef.current
      const next = rowNavStep(e.key, current, rows.length)
      if (next !== null) {
        e.preventDefault()
        keyboardMoveRef.current = true
        setActive(next)
        return
      }
      const project = rows[current]
      if (!project) return
      const onControl = e.target instanceof HTMLElement && Boolean(e.target.closest('a, button, [role="button"]'))
      if (e.key === 'Enter' && !onControl) {
        e.preventDefault()
        onOpen(project)
      } else if (e.key === 'r') {
        e.preventDefault()
        onNewRun(project)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [rows, onOpen, onNewRun])

  useEffect(() => {
    if (!keyboardMoveRef.current || active < 0) return
    keyboardMoveRef.current = false
    const row = listRef.current?.querySelectorAll<HTMLElement>('[data-slot=project-row]')[active]
    row?.querySelector<HTMLElement>('[data-slot=project-name-link]')?.focus({ preventScroll: true })
    row?.scrollIntoView({ block: 'nearest' })
  }, [active])

  // A new filter result starts unengaged; a shrinking list clamps.
  useEffect(() => { setActive(-1) }, [rows])

  return { active: active < rows.length ? active : -1, setActive, listRef }
}

function Workspace() {
  const { workspace, projects, hasModel, poolHealth, githubPatStatus } = Route.useLoaderData()
  const search = Route.useSearch()
  const navigate = useNavigate()
  const shell = useShell()
  const now = useNow()
  const [modalOpen, setModalOpen] = useState(Boolean(search.new))
  const [filter, setFilter] = useState('')

  useEffect(() => {
    if (search.new) {
      setModalOpen(true)
      void navigate({ to: '/', search: {}, replace: true })
    }
  }, [search.new, navigate])

  useEffect(() => {
    if (!shell) return
    shell.registerNewProjectHandler(() => setModalOpen(true))
    return () => shell.registerNewProjectHandler(null)
  }, [shell])

  const visibleProjects = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return projects
    return projects.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.environment.toLowerCase().includes(q) ||
      p.seeds.some(s => host(s).toLowerCase().includes(q)),
    )
  }, [projects, filter])

  const disambiguators = useMemo(
    () => projectDisambiguators(projects.map(p => ({ id: p.id, name: p.name, hosts: p.seeds.map(host) }))),
    [projects],
  )
  const openProject = useCallback((p: WorkspaceProject) => {
    void navigate({ to: '/projects/$projectId', params: { projectId: p.id } })
  }, [navigate])
  const openNewRun = useCallback((p: WorkspaceProject) => {
    void navigate({ to: '/projects/$projectId', params: { projectId: p.id }, search: { newRun: '1' } })
  }, [navigate])
  const rowNav = useProjectRowNav(visibleProjects, openProject, openNewRun)

  return <main className="flex min-h-0 flex-1 flex-col">
    <header className="sticky top-0 z-10 flex h-11 min-w-0 flex-none items-center gap-2.5 border-b border-line bg-panel px-[18px] max-[720px]:h-auto max-[720px]:min-h-11 max-[720px]:flex-wrap max-[720px]:gap-y-2 max-[720px]:px-3.5 max-[720px]:py-2">
      <h1 className="m-0 whitespace-nowrap text-[13.5px] font-semibold tracking-[-0.01em] text-fg">Projects</h1>
      {projects.length > 0 && (
        <span className="whitespace-nowrap text-[12.5px] font-normal tabular-nums text-fg-subtle" data-slot="project-count">
          {formatProjectCount(filter, visibleProjects.length, projects.length)}
        </span>
      )}
      <span className="min-w-2 flex-1" />
      {projects.length > 0 && (
        // Below 720px the filter drops to its own full-width row so it never collapses to an icon.
        <div className="flex min-w-0 shrink items-center gap-1.5 max-[720px]:contents">
          <div className="flex h-[26px] w-[200px] min-w-0 shrink items-center max-[720px]:order-last max-[720px]:w-full max-[720px]:basis-full max-[720px]:bg-sunk gap-1.5 rounded-control px-2 text-fg-subtle transition-[background-color,box-shadow] duration-[var(--d1)] hover:bg-hover focus-within:bg-sunk focus-within:text-fg-muted focus-within:shadow-hairline">
            <Icon name="search" className="flex-none" />
            <input
              type="search"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Filter…"
              aria-label="Filter projects"
              className="h-full min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 text-[12.5px] text-fg shadow-none outline-none placeholder:text-fg-subtle focus:shadow-none focus:outline-none [&::-webkit-search-cancel-button]:appearance-none [&::-webkit-search-decoration]:appearance-none"
            />
            {filter && (
              <button
                type="button"
                className="inline-flex size-6 h-6 flex-none cursor-pointer items-center justify-center rounded-sm border-0 bg-transparent p-0 text-fg-subtle shadow-none hover:bg-hover hover:text-fg"
                onClick={() => setFilter('')}
                aria-label="Clear filter"
              >
                <Icon name="x" size={12} />
              </button>
            )}
          </div>
          <Button
            variant="default"
            className="flex-none max-[720px]:size-7 max-[720px]:px-0"
            onClick={() => setModalOpen(true)}
            aria-label="New project"
          >
            <Icon name="plus" />
            <span className="max-[720px]:sr-only">New project</span>
          </Button>
        </div>
      )}
    </header>

    {!hasModel && (
      <ModelPoolBanner
        title="Connect an AI model to run assessments."
        body="Add an OpenRouter or compatible model profile in Settings."
        cta="Set up model"
      />
    )}

    {hasModel && poolHealth === 'degraded' && (
      <ModelPoolBanner
        title="Some model profiles are temporarily unavailable."
        body="One or more enabled models are cooling down after recent errors."
        cta="Settings"
      />
    )}

    {projects.length === 0 ? (
      <div className="flex-1 overflow-auto px-8 pb-14 pt-10 max-[720px]:px-4 max-[720px]:pt-6">
        <div className="mx-auto max-w-[620px]">
          <div className="inline-flex items-center gap-2 text-[12px] font-medium text-fg-subtle">
            {workspace.name}
          </div>
          <h2 className="mb-1.5 mt-2 text-[22px] font-semibold leading-[29px] tracking-[-0.02em] text-fg">
            Start your first project
          </h2>
          <p className="mb-5 max-w-[520px] text-[13px] leading-5 text-fg-muted">
            Register the hosts you own or have written authorization to test. Kovo verifies scope before dispatching any live requests.
          </p>
          <CreateProjectSheet
            isModal={false}
            canCancel={false}
            githubPatStatus={githubPatStatus}
            onClose={() => setModalOpen(false)}
          />
        </div>
      </div>
    ) : (
      <div className="min-h-0 flex-1 overflow-auto" ref={rowNav.listRef}>
        {visibleProjects.length > 0 && (
          <div
            className={cn(
              'sticky top-0 z-[2] grid h-8 items-center gap-3 border-b border-line bg-sunk px-[18px] text-[11.5px] font-medium text-fg-subtle',
              PROJECT_GRID_COLS,
            )}
            role="row"
          >
            <span>Project</span>
            <span className="max-[960px]:hidden">Seed host(s)</span>
            <span className="max-[720px]:hidden">Latest run</span>
            <span className="text-right">Runs / Findings</span>
            <span className="max-[720px]:hidden"><span className="sr-only">Actions</span></span>
          </div>
        )}

        {visibleProjects.length === 0 ? (
          <EmptyState
            title="No matching projects"
            description={`Nothing matches “${filter.trim()}” in project names, environments, or seed hosts.`}
            className="py-14"
            action={(
              <>
                <Button variant="outline" onClick={() => setFilter('')}>Clear filter</Button>
                <Button variant="default" onClick={() => setModalOpen(true)}>New project</Button>
              </>
            )}
          />
        ) : visibleProjects.map((project, index) => (
          <ProjectRow
            key={project.id}
            project={project}
            now={now}
            active={index === rowNav.active}
            disambiguator={disambiguators.get(project.id)}
            onOpen={() => openProject(project)}
            onFocusRow={() => rowNav.setActive(index)}
          />
        ))}
      </div>
    )}

    {projects.length > 0 && (
      <CreateProjectSheet
        isModal={true}
        open={modalOpen}
        canCancel={true}
        githubPatStatus={githubPatStatus}
        onClose={() => setModalOpen(false)}
      />
    )}
  </main>
}
