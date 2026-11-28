import { Link } from '@tanstack/react-router'
import { useEffect, useId, useRef, useState } from 'react'
import { listGithubRepositories } from '../../actions.ts'
import { cn } from '../../lib/cn.ts'
import type { GithubAppInstallationSummary } from '../../server/github-connector.ts'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button, buttonVariants } from '../ui/button.tsx'
import { GithubInstallBanner } from './GithubInstallBanner.tsx'
import { GroupedRepoPicker } from './GroupedRepoPicker.tsx'
import type { DiscoveredGithubRepo } from './types.ts'

export interface GithubPatStatusSummary {
  configured: boolean
  source: 'vault' | 'fixture' | null
  tokenKind: 'fine_grained' | 'classic' | 'github_app' | 'unknown' | null
  authKind?: 'github_app_device' | 'pat' | null
  login?: string | null
  expiresAt?: string | null
  githubDeviceFlowConfigured?: boolean
  clientIdSource?: 'env' | 'vault' | null
  appSlug?: string | null
  installUrl?: string | null
  installations?: GithubAppInstallationSummary[]
  privateRepoCount?: number
  needsAppInstall?: boolean
}

interface Props {
  initialPatStatus: GithubPatStatusSummary
  selectedRepos: string[]
  onChangeSelectedRepos: (repos: string[]) => void
  disabled?: boolean
}

const MAX_SYNC_REPOS = 20

function connectionBadge(status: GithubPatStatusSummary): string {
  if (status.login) return `@${status.login}`
  return 'Connected'
}

/** Crisp 16px monochrome GitHub mark for compact connected header bar. */
function GithubMarkIcon() {
  return (
    <svg
      className="block flex-none text-fg-muted"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M8 1C4.13 1 1 4.13 1 8c0 3.09 2.01 5.71 4.79 6.64.35.06.48-.15.48-.34 0-.17-.01-.72-.01-1.31-1.76.32-2.21-.43-2.35-.83-.08-.2-.42-.83-.72-.99-.24-.13-.59-.46-.01-.47.55-.01.94.51 1.07.72.63 1.05 1.63.76 2.03.58.06-.45.25-.76.45-.93-1.56-.18-3.19-.78-3.19-3.47 0-.76.27-1.39.72-1.88-.07-.18-.32-.89.07-1.85 0 0 .59-.19 1.93.72a6.7 6.7 0 0 1 3.51 0c1.34-.91 1.93-.72 1.93-.72.39.96.14 1.67.07 1.85.45.49.72 1.11.72 1.88 0 2.7-1.64 3.29-3.2 3.47.25.22.47.64.47 1.3 0 .94-.01 1.69-.01 1.93 0 .19.13.41.48.34A7.002 7.002 0 0 0 15 8c0-3.87-3.13-7-7-7Z"
      />
    </svg>
  )
}

/** sessionStorage key for the in-progress New project draft (non-secret fields only). */
export const NEW_PROJECT_DRAFT_KEY = 'kovo:new-project-draft'

export interface NewProjectDraft {
  name: string
  sites: string
}

/** Serialises only the non-secret `name` / `sites` fields; returns null when there is nothing worth keeping. */
export function serializeProjectDraft(draft: Partial<NewProjectDraft>): string | null {
  const name = typeof draft.name === 'string' ? draft.name.slice(0, 160) : ''
  const sites = typeof draft.sites === 'string' ? draft.sites.slice(0, 20_000) : ''
  if (!name.trim() && !sites.trim()) return null
  return JSON.stringify({ name, sites })
}

/** Parses a stored draft defensively: unknown keys are dropped, wrong types yield null. */
export function parseProjectDraft(raw: string | null | undefined): NewProjectDraft | null {
  if (!raw) return null
  try {
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object') return null
    const { name, sites } = value as Record<string, unknown>
    if (typeof name !== 'string' || typeof sites !== 'string') return null
    if (!name.trim() && !sites.trim()) return null
    return { name: name.slice(0, 160), sites: sites.slice(0, 20_000) }
  } catch {
    return null
  }
}

function sessionStore(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.sessionStorage
  } catch {
    return null
  }
}

type DraftField = HTMLInputElement | HTMLTextAreaElement

function draftFields(root: HTMLElement | null): { name: DraftField | null; sites: DraftField | null } {
  const form = root?.closest('form')
  const pick = (fieldName: string): DraftField | null => {
    const el = form?.elements.namedItem(fieldName)
    return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement ? el : null
  }
  return { name: pick('name'), sites: pick('seeds') }
}

/** Saves the surrounding form's name/sites before leaving for Settings. */
function persistDraftFrom(root: HTMLElement | null) {
  const store = sessionStore()
  if (!store) return
  const fields = draftFields(root)
  const serialized = serializeProjectDraft({ name: fields.name?.value, sites: fields.sites?.value })
  try {
    if (serialized) store.setItem(NEW_PROJECT_DRAFT_KEY, serialized)
  } catch {
    // Storage full or disabled: navigation still proceeds, only the draft is lost.
  }
}

/** Restores a saved draft into empty fields once, then clears it. */
function useRestoreProjectDraft(rootRef: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    const store = sessionStore()
    if (!store) return
    const draft = parseProjectDraft(store.getItem(NEW_PROJECT_DRAFT_KEY))
    if (!draft) return
    const fields = draftFields(rootRef.current)
    if (!fields.name && !fields.sites) return
    if (fields.name && !fields.name.value) fields.name.value = draft.name
    if (fields.sites && !fields.sites.value) fields.sites.value = draft.sites
    store.removeItem(NEW_PROJECT_DRAFT_KEY)
  }, [rootRef])
}

export function CreateProjectGithubBlock({
  initialPatStatus,
  selectedRepos,
  onChangeSelectedRepos,
  disabled = false,
}: Props) {
  const [patStatus, setPatStatus] = useState<GithubPatStatusSummary>(initialPatStatus)
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [repos, setRepos] = useState<DiscoveredGithubRepo[]>([])
  const [reposLoaded, setReposLoaded] = useState(false)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(false)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const panelId = useId()
  useRestoreProjectDraft(rootRef)

  useEffect(() => {
    setPatStatus(initialPatStatus)
  }, [initialPatStatus])

  useEffect(() => {
    if (!patStatus.configured || reposLoaded) return
    let cancelled = false
    setLoadingRepos(true)
    setError('')
    void listGithubRepositories()
      .then(result => {
        if (cancelled) return
        setPatStatus(result.status)
        setRepos(result.repos)
        setReposLoaded(true)
        if (result.repos.length === 1) {
          onChangeSelectedRepos([result.repos[0]!.fullName])
        }
      })
      .catch(err => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Could not load GitHub repositories.')
      })
      .finally(() => {
        if (!cancelled) setLoadingRepos(false)
      })
    return () => { cancelled = true }
  }, [patStatus.configured, reposLoaded, onChangeSelectedRepos])

  async function handleRefresh() {
    if (loadingRepos || disabled) return
    setLoadingRepos(true)
    setError('')
    try {
      const result = await listGithubRepositories()
      setPatStatus(result.status)
      setRepos(result.repos)
      setReposLoaded(true)
      if (result.repos.length === 1 && selectedRepos.length === 0) {
        onChangeSelectedRepos([result.repos[0]!.fullName])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not refresh repositories.')
    } finally {
      setLoadingRepos(false)
    }
  }

  const settingsLinkClass = cn(buttonVariants({ variant: 'ghost' }), 'h-6 px-[7px] text-[12px] text-fg-muted no-underline')

  if (!patStatus.configured) {
    return (
      <div
        ref={rootRef}
        data-slot="create-project-github"
        className="flex min-h-9 min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1.5 rounded-card border border-line-2 bg-sunk py-[5px] pl-3 pr-[5px] dark:bg-raise"
      >
        <GithubMarkIcon />
        <strong className="flex-none text-[12.5px] font-semibold leading-[18px] text-fg">Connect GitHub</strong>
        <Badge className="h-[18px] shrink-0 bg-panel text-[11px] font-medium tracking-[0.01em] text-fg-muted">
          Recommended
        </Badge>
        <span
          className="min-w-0 flex-[1_1_120px] truncate text-[12px] font-normal leading-[17px] text-fg-muted"
          title="Add source code to find deeper vulnerabilities. Connect GitHub in Settings anytime; your draft is kept."
        >
          Add source code to find deeper vulnerabilities.
        </span>
        <Link
          to="/settings"
          search={{}}
          onClick={() => persistDraftFrom(rootRef.current)}
          className={cn(
            buttonVariants({ variant: 'outline' }),
            'flex-none no-underline max-[520px]:w-full max-[520px]:justify-center',
            disabled && 'pointer-events-none opacity-50',
          )}
        >
          <span>Connect in Settings</span>
          <Icon name="arrowR" size={13} />
        </Link>
      </div>
    )
  }

  const repoStatus = loadingRepos && !reposLoaded
    ? 'Loading repositories…'
    : error
      ? 'Could not load repositories'
      : patStatus.needsAppInstall
        ? 'App not installed on any account yet'
        : reposLoaded
          ? `${repos.length} ${repos.length === 1 ? 'repository' : 'repositories'} available · optional`
          : 'Optional'

  return (
    <div ref={rootRef} data-slot="create-project-github" className="overflow-hidden rounded-card border border-line-2 bg-panel">
      <div className="flex min-h-9 min-w-0 items-center gap-2 bg-sunk py-[5px] pl-3 pr-[5px]">
        <GithubMarkIcon />
        <strong className="flex-none text-[12.5px] font-semibold leading-[18px] text-fg">GitHub</strong>
        <Badge className="max-w-[160px] flex-none bg-panel font-medium text-fg-muted">
          {connectionBadge(patStatus)}
        </Badge>
        {selectedRepos.length > 0 && (
          <Badge variant="accent" className="flex-none text-[11px] font-medium tabular-nums">
            {selectedRepos.length} selected
          </Badge>
        )}
        <span className="min-w-0 flex-1 truncate text-[12px] text-fg-subtle" title={repoStatus}>{repoStatus}</span>
        {expanded && (
          <>
            <Link to="/settings" search={{}} onClick={() => persistDraftFrom(rootRef.current)} className={cn(settingsLinkClass, 'max-[520px]:hidden')}>
              Settings
            </Link>
            <Button
              type="button"
              variant="ghost"
              className="h-6 flex-none px-[7px] text-[12px] text-fg-muted"
              disabled={loadingRepos || disabled}
              onClick={() => void handleRefresh()}
            >
              {loadingRepos ? 'Loading…' : 'Refresh'}
            </Button>
          </>
        )}
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={panelId}
          className="inline-flex h-[26px] flex-none cursor-pointer items-center gap-1 whitespace-nowrap rounded-[6px] border border-line-2 bg-panel px-2 text-[12px] font-medium text-fg shadow-none hover:bg-hover"
          onClick={() => setExpanded(open => !open)}
        >
          {expanded ? 'Hide repos' : 'Choose repos'}
          <Icon
            name="chevD"
            size={12}
            className={cn('text-fg-subtle transition-[rotate] duration-150 ease-kovo motion-reduce:transition-none', expanded && 'rotate-180')}
          />
        </button>
      </div>

      {expanded && (
        <div id={panelId} className="border-t border-line transition-opacity duration-150 ease-kovo starting:opacity-0">
          <GithubInstallBanner
            authKind={patStatus.authKind}
            tokenKind={patStatus.tokenKind}
            login={patStatus.login}
            installUrl={patStatus.installUrl}
            installations={patStatus.installations}
            privateRepoCount={patStatus.privateRepoCount}
            needsAppInstall={patStatus.needsAppInstall}
            loading={loadingRepos}
            onRefresh={() => void handleRefresh()}
            compact
            flush
          />

          <div className="border-t border-line bg-panel">
            {loadingRepos && !reposLoaded ? (
              <div className="px-3.5 py-3 text-[12.5px]">
                <span className="text-fg-subtle">Loading repositories…</span>
              </div>
            ) : error ? (
              <div className="flex items-center justify-between gap-2 px-3.5 py-3 text-[12.5px]">
                <span role="alert" className="text-[12px] text-danger">{error}</span>
                <Button type="button" variant="ghost" onClick={() => void handleRefresh()}>Retry</Button>
              </div>
            ) : (
              <GroupedRepoPicker
                repos={repos}
                selectedRepos={selectedRepos}
                onChangeSelectedRepos={onChangeSelectedRepos}
                search={search}
                onSearchChange={setSearch}
                maxSelectable={MAX_SYNC_REPOS}
                disabled={disabled}
                variant="compact"
                emptyMessage="No repositories found. You can sync repos later in the project."
              />
            )}
          </div>
        </div>
      )}
    </div>
  )
}
