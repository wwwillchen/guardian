import { useNavigate } from '@tanstack/react-router'
import { Popover } from '@base-ui/react/popover'
import { useEffect, useId, useRef, useState } from 'react'
import { createRun } from '../../actions.ts'
import type { ApprovalPolicy, CapabilityTier, PublicPersona } from '../../domain.ts'
import {
  defaultBudgetRequests,
  maxBudgetRequests,
  maxRpsPerOriginCeiling,
} from '../../domain.ts'
import { cn } from '../../lib/cn.ts'
import { useAction } from '../common.tsx'
import { Icon } from '../run/icons.tsx'
import { Badge } from '../ui/badge.tsx'
import { Button } from '../ui/button.tsx'
import { Checkbox } from '../ui/checkbox.tsx'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { Input, Textarea } from '../ui/input.tsx'
import { PersonaFormModal } from './PersonaFormModal.tsx'
import type { PersonaTestState, ProjectLoaderData } from './types.ts'
import { formatPersonaAuthBadge } from './types.ts'

interface Props {
  open: boolean
  onClose: () => void
  data: ProjectLoaderData
  selectedPersonaIds: string[]
  setSelectedPersonaIds: React.Dispatch<React.SetStateAction<string[]>>
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
}

type ScanMode = 'passive' | 'supervised' | 'autonomous'

interface ScanModePreset {
  key: ScanMode
  usdCap: number
  rps: number
  goal: string
  label: string
  badge: string
  desc: string
  badgeVariant: 'neutral' | 'accent' | 'warn'
  warning?: string
}

const SCAN_MODES: Record<ScanMode, ScanModePreset> = {
  passive: {
    key: 'passive',
    usdCap: 15,
    rps: 4,
    goal: 'Map endpoints, API routes, and client bundles, and verify read-only exposures and cross-account reads without state-changing requests.',
    label: 'Passive Scan',
    badge: 'Safest',
    desc: 'Read-only discovery and checks; never mutates state.',
    badgeVariant: 'neutral',
  },
  supervised: {
    key: 'supervised',
    usdCap: 25,
    rps: 5,
    goal: 'Run safe active checks, auth/access-control probes, and high-impact proofs while pausing for human approval before risky state-changing actions.',
    label: 'Supervised Scan',
    badge: 'Recommended',
    desc: 'Safe active checks; pauses for approval before risky writes.',
    badgeVariant: 'accent',
  },
  autonomous: {
    key: 'autonomous',
    usdCap: 30,
    rps: 5,
    goal: 'Run all in-scope active probes, mutations, and race bursts automatically with full audit logs and no approval pauses.',
    label: 'Autonomous Scan',
    badge: 'Risky',
    desc: 'Runs write probes automatically without pausing for approval. Best for staging or local labs.',
    badgeVariant: 'warn',
    warning: 'Not recommended for production environments',
  },
}

const SCAN_MODE_ORDER: readonly ScanMode[] = ['passive', 'supervised', 'autonomous']
const BUDGET_CHIPS = [10, 25, 50] as const

const MODE_ICON: Record<ScanMode, 'search' | 'shield' | 'play'> = {
  passive: 'search',
  supervised: 'shield',
  autonomous: 'play',
}

/** Chips shown before the "+N" overflow pill; six fit two lines of the 680px sheet. */
export const MAX_VISIBLE_ACCOUNT_CHIPS = 5

/**
 * Selected-account chip row: show every chip when one more would not need a
 * "+1" pill, otherwise cap at `max` and report the rest as overflow.
 */
export function summarizeAccountChips<T>(selected: readonly T[], max = MAX_VISIBLE_ACCOUNT_CHIPS): { visible: T[]; overflow: number } {
  if (selected.length <= max + 1) return { visible: [...selected], overflow: 0 }
  return { visible: selected.slice(0, max), overflow: selected.length - max }
}

/** Case-insensitive match on handle, account label, tenant, and auth summary. */
export function filterAccounts<T extends Pick<PublicPersona, 'handle' | 'roleLabel'> & { tenantRef?: string | null }>(
  personas: readonly T[],
  query: string,
  describe: (persona: T) => string = () => '',
): T[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return [...personas]
  return personas.filter(persona =>
    [persona.handle, persona.roleLabel, persona.tenantRef ?? '', describe(persona)]
      .some(field => field.toLowerCase().includes(needle)),
  )
}

/** "4 of 12 selected" */
export function formatAccountSelection(selected: number, total: number): string {
  return `${selected} of ${total} selected`
}

export function resolveRunSubmissionMode(
  scanMode: ScanMode,
  selectedPersonaCount: number,
): { capabilityTier: CapabilityTier; approvalPolicy: ApprovalPolicy } {
  if (scanMode === 'passive') {
    return {
      capabilityTier: selectedPersonaCount > 0 ? 2 : 1,
      approvalPolicy: 'auto_review',
    }
  }
  if (scanMode === 'supervised') {
    return {
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
    }
  }
  return {
    capabilityTier: 3,
    approvalPolicy: 'yolo',
  }
}

/** Parsed + validated run limits; the raw strings stay in state so clearing a field never coerces to 0. */
export function parseRunLimits(input: {
  budgetText: string
  rateText: string
  reqsText: string
  unlimitedReqs: boolean
}): {
  budgetUsd: number | null
  maxRps: number | null
  budgetReqs: number | null
  errors: { budget?: string; rate?: string; reqs?: string }
} {
  const errors: { budget?: string; rate?: string; reqs?: string } = {}
  const budgetRaw = input.budgetText.trim()
  const budget = budgetRaw === '' ? Number.NaN : Number(budgetRaw)
  const budgetOk = Number.isFinite(budget) && budget >= 0.1 && budget <= 500
  if (!budgetOk) errors.budget = budgetRaw === '' ? 'Enter a spend cap between $0.10 and $500.' : 'Spend cap must be between $0.10 and $500.'
  const rateRaw = input.rateText.trim()
  const rate = rateRaw === '' ? Number.NaN : Number(rateRaw)
  const rateOk = Number.isInteger(rate) && rate >= 1 && rate <= maxRpsPerOriginCeiling
  if (!rateOk) errors.rate = `Rate must be a whole number from 1 to ${maxRpsPerOriginCeiling} req/s.`
  const reqsRaw = input.reqsText.trim()
  const reqs = reqsRaw === '' ? Number.NaN : Number(reqsRaw)
  const reqsOk = input.unlimitedReqs || (Number.isInteger(reqs) && reqs >= 1 && reqs <= maxBudgetRequests)
  if (!reqsOk) errors.reqs = `Max requests must be a whole number from 1 to ${maxBudgetRequests.toLocaleString('en-US')}.`
  return {
    budgetUsd: budgetOk ? budget : null,
    maxRps: rateOk ? rate : null,
    budgetReqs: input.unlimitedReqs ? 0 : reqsOk ? reqs : null,
    errors,
  }
}

function verifyLabelFor(test: PersonaTestState | undefined): string {
  if (test?.status === 'testing') return 'Verifying…'
  if (test?.status === 'ok') return 'Verified ✓'
  if (test?.status === 'warn') return 'Retry sign-in'
  if (test?.status === 'error') return 'Sign-in failed'
  return 'Verify sign-in'
}

function verifyToneFor(test: PersonaTestState | undefined): string {
  if (test?.status === 'ok') return 'text-ok'
  if (test?.status === 'warn') return 'text-warn'
  if (test?.status === 'error') return 'text-danger'
  return 'text-fg-subtle hover:text-fg'
}

function SelectedCheck() {
  return (
    <svg viewBox="0 0 12 12" className="size-[9px]" aria-hidden="true">
      <path d="m2.5 6.2 2.2 2.2 4.8-5" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function PersonaPill({
  persona,
  selected,
  test,
  onToggle,
  onTestPersona,
}: {
  persona: PublicPersona
  selected: boolean
  test: PersonaTestState | undefined
  onToggle: () => void
  onTestPersona: (persona: PublicPersona) => void
}) {
  return (
    <div
      data-slot="persona-pill"
      className={cn(
        'inline-flex h-[26px] min-w-0 max-w-[min(200px,100%)] items-center overflow-hidden rounded-full border transition-colors',
        selected
          ? 'border-accent-line bg-accent-soft text-fg'
          : 'border-line-2 bg-sunk text-fg-muted',
      )}
    >
      <button
        type="button"
        aria-pressed={selected}
        aria-label={`${persona.handle} selected for this run (click to remove)`}
        className="inline-flex h-full min-w-0 flex-1 cursor-pointer items-center gap-1.5 whitespace-nowrap border-0 bg-transparent py-0 pl-2 pr-1.5 text-[12px] font-medium text-inherit shadow-none transition-colors hover:bg-hover/60"
        onClick={onToggle}
        title={`${persona.handle} · ${persona.roleLabel} (${formatPersonaAuthBadge(persona)})`}
      >
        <span
          className={cn(
            'inline-grid size-[13px] flex-none place-items-center rounded-full border',
            selected
              ? 'border-accent bg-accent text-accent-fg'
              : 'border-line-strong text-transparent',
          )}
          aria-hidden="true"
        >
          <SelectedCheck />
        </span>
        <span className="min-w-0 truncate font-mono text-[12px]">{persona.handle}</span>
      </button>
      <button
        type="button"
        disabled={test?.status === 'testing'}
        className={cn(
          'inline-flex h-full flex-none cursor-pointer items-center whitespace-nowrap border-0 border-l border-line/80 bg-transparent px-2 py-0 text-[11px] font-medium shadow-none transition-colors hover:bg-hover/80 disabled:cursor-default disabled:opacity-60',
          verifyToneFor(test),
        )}
        aria-label={`Verify sign-in for ${persona.handle}`}
        title={test?.message ?? `Verify sign-in for ${persona.handle}`}
        onClick={() => onTestPersona(persona)}
      >
        {verifyLabelFor(test)}
      </button>
    </div>
  )
}

function QuietAction({ children, className, ...props }: React.ComponentProps<'button'>) {
  return (
    <button
      type="button"
      className={cn(
        'h-6 cursor-pointer whitespace-nowrap rounded-[5px] border-0 bg-transparent px-[7px] text-[11.5px] font-medium text-fg-muted shadow-none transition-colors hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45 disabled:hover:bg-transparent',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
}

/**
 * Searchable multi-select account picker ([U12]): a summary header, an
 * input-like trigger that opens a listbox popover with search, and a compact
 * chip row of the selected accounts capped to two lines with a "+N" overflow.
 */
function AccountCombobox({
  personas,
  selectedIds,
  setSelectedIds,
  personaTests,
  onTestPersona,
  onAddAccount,
}: {
  personas: readonly PublicPersona[]
  selectedIds: readonly string[]
  setSelectedIds: React.Dispatch<React.SetStateAction<string[]>>
  personaTests: Record<string, PersonaTestState>
  onTestPersona: (persona: PublicPersona) => void
  onAddAccount: () => void
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const searchRef = useRef<HTMLInputElement | null>(null)
  const listboxId = useId()

  const selectedSet = new Set(selectedIds)
  const matches = filterAccounts(personas, query, formatPersonaAuthBadge)
  const selectedPersonas = selectedIds
    .map(id => personas.find(persona => persona.id === id))
    .filter((persona): persona is PublicPersona => Boolean(persona))
  const chips = summarizeAccountChips(selectedPersonas)
  const activeOption = matches[Math.min(activeIndex, Math.max(0, matches.length - 1))]

  function toggle(id: string) {
    setSelectedIds(prev => (prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]))
  }

  function onSearchKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      if (matches.length === 0) return
      const delta = event.key === 'ArrowDown' ? 1 : -1
      setActiveIndex(index => (Math.min(index, matches.length - 1) + delta + matches.length) % matches.length)
      return
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      if (activeOption) toggle(activeOption.id)
    }
  }

  return (
    <div className="flex min-w-0 flex-col gap-2" data-slot="account-combobox">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="inline-flex min-w-0 items-baseline gap-2 text-[12px] font-semibold text-fg">
          Test accounts
          {personas.length > 0 && (
            <span className="font-normal tabular-nums text-fg-subtle" data-slot="account-selection-count">
              {formatAccountSelection(selectedPersonas.length, personas.length)}
            </span>
          )}
        </span>
        <div className="flex flex-wrap items-center gap-0.5">
          {personas.length > 1 && (
            <QuietAction
              disabled={selectedPersonas.length === personas.length}
              onClick={() => setSelectedIds(personas.map(persona => persona.id))}
            >
              Select all
            </QuietAction>
          )}
          {selectedPersonas.length > 0 && (
            <>
              <QuietAction onClick={() => setSelectedIds([])}>Clear</QuietAction>
              {selectedPersonas.length > 1 && (
                <QuietAction onClick={() => selectedPersonas.forEach(persona => onTestPersona(persona))}>
                  Verify all
                </QuietAction>
              )}
            </>
          )}
          <Button type="button" variant="outline" className="ml-1" onClick={onAddAccount}>
            + Add test account
          </Button>
        </div>
      </div>

      {personas.length === 0 ? (
        <span className="text-[12px] text-fg-subtle">
          No test accounts configured yet — add User A &amp; User B to test signed-in views and cross-user isolation.
        </span>
      ) : (
        <>
          <Popover.Root
            open={open}
            onOpenChange={next => {
              setOpen(next)
              if (!next) {
                setQuery('')
                setActiveIndex(0)
              }
            }}
          >
            <Popover.Trigger
              data-slot="account-combobox-trigger"
              aria-label="Choose test accounts for this run"
              className="flex h-[30px] w-full min-w-0 cursor-pointer items-center gap-2 whitespace-nowrap rounded-[6px] border border-line-2 bg-panel px-2.5 text-left text-[12px] font-normal text-fg-subtle shadow-none transition-colors hover:border-line-strong hover:bg-panel data-[popup-open]:border-accent-line"
            >
              <Icon name="search" size={13} className="flex-none" />
              <span className="min-w-0 flex-1 truncate">
                {`Search ${personas.length} test ${personas.length === 1 ? 'account' : 'accounts'}…`}
              </span>
              <Icon name="chevD" size={12} className="flex-none" />
            </Popover.Trigger>
            <Popover.Portal>
              <Popover.Positioner side="bottom" align="start" sideOffset={4} className="z-[70]">
                <Popover.Popup
                  initialFocus={searchRef}
                  data-slot="account-combobox-popup"
                  className={cn(
                    'flex w-[var(--anchor-width)] max-w-[calc(100vw-32px)] flex-col overflow-hidden rounded-card border border-line-2 bg-raise text-fg shadow-popover outline-none',
                    'origin-[var(--transform-origin)] transition-[opacity,scale] duration-150 ease-kovo data-[ending-style]:scale-[.98] data-[ending-style]:opacity-0 data-[starting-style]:scale-[.98] data-[starting-style]:opacity-0',
                  )}
                >
                  <div className="flex h-9 flex-none items-center gap-2 border-b border-line px-2.5">
                    <Icon name="search" size={13} className="flex-none text-fg-subtle" />
                    <input
                      ref={searchRef}
                      type="search"
                      role="combobox"
                      aria-expanded="true"
                      aria-controls={listboxId}
                      aria-autocomplete="list"
                      aria-activedescendant={activeOption ? `${listboxId}-${activeOption.id}` : undefined}
                      aria-label="Search test accounts"
                      placeholder="Search by handle, label, or tenant…"
                      className="h-[26px] w-full min-w-0 flex-1 rounded-none border-0 bg-transparent p-0 text-[12.5px] shadow-none outline-none focus:shadow-none [&::-webkit-search-cancel-button]:appearance-none"
                      value={query}
                      onChange={event => {
                        setQuery(event.target.value)
                        setActiveIndex(0)
                      }}
                      onKeyDown={onSearchKeyDown}
                    />
                  </div>
                  <div
                    id={listboxId}
                    role="listbox"
                    aria-multiselectable="true"
                    aria-label="Test accounts"
                    className="max-h-[232px] overflow-y-auto p-1"
                  >
                    {matches.length === 0 ? (
                      <div className="px-2 py-3 text-[12px] text-fg-subtle">No test accounts match “{query.trim()}”.</div>
                    ) : matches.map(persona => {
                      const checked = selectedSet.has(persona.id)
                      const active = activeOption?.id === persona.id
                      const test = personaTests[persona.id]
                      return (
                        <div
                          key={persona.id}
                          id={`${listboxId}-${persona.id}`}
                          role="option"
                          aria-selected={checked}
                          data-active={active ? 'true' : undefined}
                          className="flex min-h-[36px] cursor-pointer select-none items-center gap-2 rounded-[6px] px-2 py-1 data-[active=true]:bg-hover hover:bg-hover"
                          onMouseDown={event => event.preventDefault()}
                          onMouseEnter={() => setActiveIndex(matches.indexOf(persona))}
                          onClick={() => toggle(persona.id)}
                        >
                          <span
                            aria-hidden="true"
                            className={cn(
                              'inline-grid size-[14px] flex-none place-items-center rounded-[4px] border',
                              checked ? 'border-accent bg-accent text-accent-fg' : 'border-line-strong text-transparent',
                            )}
                          >
                            <SelectedCheck />
                          </span>
                          <span className="flex min-w-0 flex-1 flex-col">
                            <span className="truncate font-mono text-[12px] font-medium text-fg">{persona.handle}</span>
                            <span className="truncate text-[11px] text-fg-subtle">
                              {[persona.roleLabel, persona.tenantRef, formatPersonaAuthBadge(persona)].filter(Boolean).join(' · ')}
                            </span>
                          </span>
                          {test && (
                            <span className={cn('flex-none text-[11px] font-medium', verifyToneFor(test))}>{verifyLabelFor(test)}</span>
                          )}
                        </div>
                      )
                    })}
                  </div>
                  <div className="flex flex-none items-center justify-between gap-2 border-t border-line px-2.5 py-1.5 text-[11.5px] text-fg-subtle">
                    <span className="tabular-nums">{formatAccountSelection(selectedPersonas.length, personas.length)}</span>
                    <Popover.Close
                      className="h-6 cursor-pointer rounded-[5px] border-0 bg-transparent px-[7px] text-[11.5px] font-medium text-accent shadow-none hover:bg-hover"
                    >
                      Done
                    </Popover.Close>
                  </div>
                </Popover.Popup>
              </Popover.Positioner>
            </Popover.Portal>
          </Popover.Root>

          {chips.visible.length > 0 && (
            <div className="flex min-w-0 flex-wrap gap-1.5" role="group" aria-label="Selected test accounts" data-slot="account-chips">
              {chips.visible.map(persona => (
                <PersonaPill
                  key={persona.id}
                  persona={persona}
                  selected
                  test={personaTests[persona.id]}
                  onToggle={() => toggle(persona.id)}
                  onTestPersona={onTestPersona}
                />
              ))}
              {chips.overflow > 0 && (
                <button
                  type="button"
                  data-slot="account-chip-overflow"
                  aria-label={`Show ${chips.overflow} more selected test accounts`}
                  className="h-[26px] cursor-pointer whitespace-nowrap rounded-full border border-line-2 bg-sunk px-2.5 text-[11.5px] font-medium tabular-nums text-fg-muted shadow-none hover:bg-hover hover:text-fg"
                  onClick={() => setOpen(true)}
                >
                  {`+${chips.overflow}`}
                </button>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function FieldError({ id, message }: { id: string; message: string | undefined }) {
  if (!message) return null
  return (
    <p id={id} className="form-error m-0 text-[11.5px] font-normal">
      {message}
    </p>
  )
}

/** Submit error rendered in the sticky footer (never below the fold) and focused when it appears. */
function useFocusedSubmitError(error: string, pending: boolean, submitRef: React.RefObject<HTMLButtonElement | null>) {
  const errorRef = useRef<HTMLParagraphElement | null>(null)
  const wasPending = useRef(false)
  useEffect(() => {
    if (error) {
      errorRef.current?.scrollIntoView({ block: 'nearest' })
      errorRef.current?.focus()
    }
  }, [error])
  useEffect(() => {
    if (wasPending.current && !pending && !error) submitRef.current?.focus()
    wasPending.current = pending
  }, [pending, error, submitRef])
  return errorRef
}

export function ProjectNewRunSheet({
  open,
  onClose,
  data,
  selectedPersonaIds,
  setSelectedPersonaIds,
  personaTests,
  onTestPersona,
}: Props) {
  const { project, personas } = data
  const navigate = useNavigate()

  const [scanMode, setScanMode] = useState<ScanMode>('supervised')
  const [goal, setGoal] = useState('')
  const [budgetText, setBudgetText] = useState(() => String(SCAN_MODES.supervised.usdCap))
  const [rateText, setRateText] = useState(() => String(SCAN_MODES.supervised.rps))
  const [unlimitedReqs, setUnlimitedReqs] = useState<boolean>(defaultBudgetRequests === 0)
  const [reqsText, setReqsText] = useState(() => String(defaultBudgetRequests === 0 ? 2500 : defaultBudgetRequests))
  const [touched, setTouched] = useState<{ budget?: boolean; rate?: boolean; reqs?: boolean }>({})
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [addPersonaOpen, setAddPersonaOpen] = useState(false)
  const checkedModeRef = useRef<HTMLButtonElement | null>(null)
  const submitRef = useRef<HTMLButtonElement | null>(null)

  const runAction = useAction()
  const busy = runAction.pending
  const errorRef = useFocusedSubmitError(runAction.error, runAction.pending, submitRef)

  const limits = parseRunLimits({ budgetText, rateText, reqsText, unlimitedReqs })
  const shownErrors = {
    budget: touched.budget ? limits.errors.budget : undefined,
    rate: touched.rate ? limits.errors.rate : undefined,
    reqs: touched.reqs ? limits.errors.reqs : undefined,
  }

  function applyScanMode(nextMode: ScanMode) {
    const preset = SCAN_MODES[nextMode]
    setScanMode(nextMode)
    setBudgetText(String(preset.usdCap))
    setRateText(String(preset.rps))
  }

  function focusField(name: string) {
    // The Advanced panel mounts its fields on open, so wait a frame before focusing.
    requestAnimationFrame(() => {
      const el = document.querySelector<HTMLInputElement>(`[data-slot="new-run-form"] [name="${name}"]`)
      el?.focus()
    })
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const { budgetUsd, maxRps, budgetReqs, errors } = limits
    if (budgetUsd === null || maxRps === null || budgetReqs === null) {
      setTouched({ budget: true, rate: true, reqs: true })
      if (errors.budget) {
        focusField('budgetUsd')
      } else {
        setAdvancedOpen(true)
        focusField(errors.rate ? 'maxRpsPerOrigin' : 'budgetRequests')
      }
      return
    }
    const { capabilityTier, approvalPolicy } = resolveRunSubmissionMode(
      scanMode,
      selectedPersonaIds.length,
    )
    const effectiveGoal = goal.trim() || SCAN_MODES[scanMode].goal
    const effectiveReqs = unlimitedReqs ? 0 : Math.max(1, Math.min(maxBudgetRequests, Math.round(budgetReqs)))
    void runAction.submit(() => createRun({ data: {
      requestId: crypto.randomUUID(),
      projectId: project.id,
      goal: effectiveGoal,
      sourceMode: 'public',
      capabilityTier,
      approvalPolicy,
      approvedPersonaIds: selectedPersonaIds,
      budgetUsd,
      budgetRequests: effectiveReqs,
      maxRpsPerOrigin: maxRps,
    } }), async result => {
      onClose()
      await navigate({ to: '/runs/$runId', params: { runId: result.id } })
    })
  }

  const testedPersonas = personas.filter(p => Boolean(personaTests[p.id]))
  const footerSummary = [
    SCAN_MODES[scanMode].label,
    limits.budgetUsd === null ? '— cap' : `$${limits.budgetUsd} cap`,
    `${selectedPersonaIds.length} ${selectedPersonaIds.length === 1 ? 'test account' : 'test accounts'}`,
  ].join(' · ')
  const advancedSummary = [
    limits.maxRps === null ? '— req/s' : `${limits.maxRps} req/s`,
    unlimitedReqs ? 'unlimited reqs' : limits.budgetReqs === null ? '— max reqs' : `${limits.budgetReqs.toLocaleString('en-US')} max reqs`,
  ].join(' · ')

  return (
    <>
      <Dialog
        open={open}
        closeOnEscape={!busy && !addPersonaOpen}
        onOpenChange={nextOpen => {
          if (!nextOpen && !busy && !addPersonaOpen) onClose()
        }}
      >
        <DialogContent
          initialFocus={checkedModeRef}
          className="mb-auto mt-[min(12vh,96px)] flex max-h-[calc(100vh-min(12vh,96px)-32px)] max-w-[680px] flex-col overflow-hidden p-0"
        >
          <form className="flex min-h-0 flex-1 flex-col" onSubmit={handleSubmit} noValidate data-slot="new-run-form">
            <DialogHeader className="flex-row items-center justify-between gap-2.5 border-b border-line bg-raise px-4 py-2.5">
              <DialogTitle className="min-w-0 truncate text-[13px] font-semibold text-fg" title={project.name}>
                New run · {project.name}
              </DialogTitle>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-[26px] flex-none"
                onClick={onClose}
                disabled={busy}
                aria-label="Close"
              >
                <Icon name="close" size={14} />
              </Button>
            </DialogHeader>

            <DialogBody className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
              <div className="flex flex-col gap-2">
                <div
                  className="flex flex-col gap-1.5"
                  role="radiogroup"
                  aria-label="Scan mode"
                  onKeyDown={event => {
                    const delta = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? -1 : 0
                    if (!delta) return
                    event.preventDefault()
                    const index = SCAN_MODE_ORDER.indexOf(scanMode)
                    const nextMode = SCAN_MODE_ORDER[(index + delta + SCAN_MODE_ORDER.length) % SCAN_MODE_ORDER.length]!
                    applyScanMode(nextMode)
                    requestAnimationFrame(() => checkedModeRef.current?.focus())
                  }}
                >
                  {SCAN_MODE_ORDER.map(modeKey => {
                    const m = SCAN_MODES[modeKey]
                    const active = scanMode === modeKey
                    const activeClasses = modeKey === 'autonomous'
                      ? 'border-warn-line bg-warn-soft hover:bg-warn-soft'
                      : 'border-accent-line bg-accent-soft hover:bg-accent-soft'
                    return (
                      <button
                        key={modeKey}
                        ref={active ? checkedModeRef : undefined}
                        type="button"
                        role="radio"
                        aria-checked={active}
                        tabIndex={active ? 0 : -1}
                        data-slot="scan-mode-row"
                        title={m.warning ? `${m.desc} ${m.warning}.` : m.desc}
                        className={cn(
                          'flex h-auto min-h-[42px] w-full min-w-0 cursor-pointer items-center gap-2.5 whitespace-normal rounded-[8px] border px-3 py-1.5 text-left font-normal text-fg shadow-none transition-colors active:scale-100',
                          active ? activeClasses : 'border-line-2 bg-panel hover:border-line-strong hover:bg-hover',
                        )}
                        onClick={() => applyScanMode(modeKey)}
                      >
                        <span
                          aria-hidden="true"
                          className={cn(
                            'inline-grid size-4 flex-none place-items-center rounded-full border transition-colors',
                            active
                              ? modeKey === 'autonomous' ? 'border-warn bg-warn' : 'border-accent bg-accent'
                              : 'border-line-strong bg-panel',
                          )}
                        >
                          <span className={cn('size-1.5 rounded-full', active ? 'bg-panel' : 'bg-transparent')} />
                        </span>
                        <Icon
                          name={MODE_ICON[modeKey]}
                          size={16}
                          className={cn('flex-none', modeKey === 'autonomous' ? 'text-warn' : active ? 'text-accent' : 'text-fg-subtle')}
                        />
                        <span className="flex min-w-0 flex-1 items-baseline gap-2 max-[560px]:flex-col max-[560px]:gap-0">
                          <strong className="flex-none text-[12.5px] font-semibold leading-[18px] text-fg">{m.label}</strong>
                          <span className="min-w-0 truncate text-[11.5px] leading-4 text-fg-muted max-[560px]:whitespace-normal">{m.desc}</span>
                        </span>
                        <Badge
                          variant={m.badgeVariant}
                          className={cn('flex-none', m.badgeVariant === 'neutral' && 'bg-sunk')}
                        >
                          {m.badge}
                        </Badge>
                      </button>
                    )
                  })}
                </div>

                {scanMode === 'autonomous' && (
                  <div
                    role="status"
                    className="flex items-start gap-2 rounded-[7px] border border-warn-line bg-warn-soft px-3 py-1.5 text-[12px] leading-[17px] text-fg"
                  >
                    <Icon name="alert" size={14} className="mt-0.5 flex-none text-warn" />
                    <span>
                      <strong className="font-semibold">Not recommended for production environments.</strong>{' '}
                      Write probes run automatically without approval.
                    </span>
                  </div>
                )}
              </div>

              <div className="flex min-w-0 flex-col gap-2 border-t border-line pt-3">
                <AccountCombobox
                  personas={personas}
                  selectedIds={selectedPersonaIds}
                  setSelectedIds={setSelectedPersonaIds}
                  personaTests={personaTests}
                  onTestPersona={onTestPersona}
                  onAddAccount={() => setAddPersonaOpen(true)}
                />
                {testedPersonas.length > 0 && (
                  <div className="grid max-h-[52px] gap-1 overflow-y-auto" role="status">
                    {testedPersonas.map(persona => {
                      const test = personaTests[persona.id]!
                      const tone = test.status === 'ok'
                        ? 'text-ok'
                        : test.status === 'warn'
                          ? 'text-warn'
                          : test.status === 'error'
                            ? 'text-danger'
                            : 'text-fg-subtle'
                      return (
                        <div key={persona.id} className={cn('min-w-0 text-[11.5px] [overflow-wrap:anywhere]', tone)}>
                          <span className="font-mono font-medium">{persona.handle}</span>: {test.message}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              <div className="flex flex-col gap-1.5 border-t border-line pt-2.5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-[12.5px] font-semibold text-fg">Budget cap</div>
                    <div className="text-[11.5px] text-fg-subtle">Hard stop when spend reaches limit</div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {BUDGET_CHIPS.map(v => {
                      const on = limits.budgetUsd === v
                      return (
                        <button
                          key={v}
                          type="button"
                          aria-pressed={on}
                          className={cn(
                            'h-6 cursor-pointer rounded-[5px] border px-2 text-[11.5px] font-medium tabular-nums shadow-none transition-colors',
                            on
                              ? 'border-accent-line bg-accent-soft text-accent hover:bg-accent-soft'
                              : 'border-line-2 bg-panel text-fg-muted hover:bg-hover hover:text-fg',
                          )}
                          onClick={() => setBudgetText(String(v))}
                        >
                          ${v}
                        </button>
                      )
                    })}
                    <label className="inline-flex items-center gap-1 text-[12px] text-fg-muted">
                      <span>$</span>
                      <Input
                        className="h-[26px]! w-[84px] tabular-nums"
                        name="budgetUsd"
                        aria-label="USD Spend Cap"
                        type="number"
                        inputMode="decimal"
                        min={0.1}
                        max={500}
                        step="any"
                        value={budgetText}
                        aria-invalid={shownErrors.budget ? true : undefined}
                        aria-describedby={shownErrors.budget ? 'budget-err' : undefined}
                        onChange={e => setBudgetText(e.target.value)}
                        onBlur={() => setTouched(prev => ({ ...prev, budget: true }))}
                      />
                    </label>
                  </div>
                </div>
                <FieldError id="budget-err" message={shownErrors.budget} />
              </div>

              <Disclosure className="border-t border-line pt-2.5" open={advancedOpen} onOpenChange={setAdvancedOpen}>
                <DisclosureTrigger className="h-auto bg-transparent px-0 py-1 text-fg-muted shadow-none hover:bg-transparent hover:text-fg">
                  <span>
                    Advanced configuration{' '}
                    <span className="font-normal tabular-nums text-fg-subtle" data-slot="advanced-summary">
                      ({advancedSummary})
                    </span>
                  </span>
                </DisclosureTrigger>
                <DisclosureContent className="grid gap-2.5 pt-2.5">
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Run goal
                    <Textarea
                      className="w-full"
                      name="goal"
                      rows={2}
                      maxLength={8000}
                      value={goal}
                      onChange={e => setGoal(e.target.value)}
                      placeholder={SCAN_MODES[scanMode].goal}
                    />
                  </label>
                  <label className="grid gap-1 text-[12px] font-medium text-fg-muted">
                    Rate (req/s)
                    <Input
                      className="w-full tabular-nums sm:max-w-[180px]"
                      name="maxRpsPerOrigin"
                      type="number"
                      inputMode="numeric"
                      min={1}
                      max={maxRpsPerOriginCeiling}
                      step={1}
                      value={rateText}
                      aria-invalid={shownErrors.rate ? true : undefined}
                      aria-describedby={shownErrors.rate ? 'rate-err' : undefined}
                      onChange={e => setRateText(e.target.value)}
                      onBlur={() => setTouched(prev => ({ ...prev, rate: true }))}
                    />
                    <FieldError id="rate-err" message={shownErrors.rate} />
                  </label>
                  <label className="inline-flex cursor-pointer select-none items-center gap-[7px] text-[12.5px] font-normal text-fg-muted">
                    <Checkbox
                      checked={unlimitedReqs}
                      aria-label="Unlimited max requests"
                      onCheckedChange={checked => setUnlimitedReqs(Boolean(checked))}
                    />
                    <span>Unlimited requests (recommended)</span>
                  </label>
                  {!unlimitedReqs && (
                    <label
                      className="grid gap-1 text-[12px] font-medium text-fg-muted"
                      title="Maximum HTTP requests sent through the request guardrail"
                    >
                      Max requests
                      <Input
                        className="w-full tabular-nums sm:max-w-[180px]"
                        name="budgetRequests"
                        type="number"
                        inputMode="numeric"
                        min={1}
                        max={maxBudgetRequests}
                        step={1}
                        value={reqsText}
                        aria-invalid={shownErrors.reqs ? true : undefined}
                        aria-describedby={shownErrors.reqs ? 'reqs-err' : undefined}
                        onChange={e => setReqsText(e.target.value)}
                        onBlur={() => setTouched(prev => ({ ...prev, reqs: true }))}
                      />
                      <FieldError id="reqs-err" message={shownErrors.reqs} />
                    </label>
                  )}
                </DisclosureContent>
              </Disclosure>
            </DialogBody>

            <DialogFooter className="flex-wrap">
              {runAction.error && (
                <p
                  ref={errorRef}
                  role="alert"
                  tabIndex={-1}
                  data-slot="submit-error"
                  className="form-error m-0 max-h-24 basis-full overflow-y-auto text-[12px] outline-none [overflow-wrap:anywhere]"
                >
                  {runAction.error}
                </p>
              )}
              <span className="mr-auto min-w-0 font-mono text-[12px] tabular-nums text-fg-subtle" data-slot="new-run-footer-summary">
                {footerSummary}
              </span>
              <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
                Cancel
              </Button>
              <Button ref={submitRef} type="submit" variant="default" disabled={runAction.pending}>
                {runAction.pending ? 'Starting…' : 'Start run'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <PersonaFormModal
        open={addPersonaOpen}
        onClose={() => setAddPersonaOpen(false)}
        project={project}
        existingPersonas={personas}
        submitLabel="Save & select"
        onCreated={created => {
          setSelectedPersonaIds(prev => prev.includes(created.id) ? prev : [...prev, created.id])
        }}
      />
    </>
  )
}
