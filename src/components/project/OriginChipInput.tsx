import { useId, useRef, useState } from 'react'
import { cn } from '../../lib/cn.ts'
import { Icon } from '../run/icons.tsx'

/**
 * Seed-origin chip editor ([U12]): paste or type origins, each one becomes a
 * validated chip; "Edit as text" swaps to a plain textarea that stays in sync.
 *
 * The pure helpers below own all parsing so the modal, the tests, and the
 * text-mode escape hatch share one tokenizer/validator/dedupe path.
 */

export interface OriginToken {
  /** The text exactly as the user entered it (trimmed). */
  raw: string
  /** Normalised comparison key (`https://host[:port][/path]`), used for dedupe. */
  key: string
  valid: boolean
}

export interface OriginSummary {
  total: number
  invalid: number
  invalidTokens: string[]
}

const HAS_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i
const SEPARATOR_RE = /[\n,]/

/**
 * Validates one origin with `new URL()`: `http:`/`https:` only and a real host.
 * A bare hostname (`app.example.com`, `localhost:3000`) is read as `https://…`,
 * mirroring the server's seed rule (the server stays authoritative).
 */
export function normalizeOrigin(token: string): { valid: boolean; key: string } {
  const trimmed = token.trim()
  if (!trimmed) return { valid: false, key: '' }
  try {
    const url = new URL(HAS_SCHEME_RE.test(trimmed) ? trimmed : `https://${trimmed}`)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return { valid: false, key: trimmed.toLowerCase() }
    const hostname = url.hostname.replace(/^\[|\]$/g, '')
    const realHost = hostname.length > 0 && (hostname === 'localhost' || hostname.includes('.') || hostname.includes(':'))
    const path = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '')
    return { valid: realHost, key: `${url.protocol}//${url.host}${path}${url.search}` }
  } catch {
    return { valid: false, key: trimmed.toLowerCase() }
  }
}

/**
 * Splits pasted/typed text on new lines and commas, then on whitespace only
 * when every part is itself an origin — so "a.com b.com" yields two chips but
 * a phrase like "not a url" stays one (invalid) chip instead of three.
 */
export function tokenizeOrigins(text: string): string[] {
  const tokens: string[] = []
  for (const chunk of text.split(/[\n,]+/)) {
    const trimmed = chunk.trim()
    if (!trimmed) continue
    const parts = trimmed.split(/\s+/)
    if (parts.length > 1 && !parts.every(part => normalizeOrigin(part).valid)) tokens.push(trimmed)
    else tokens.push(...parts)
  }
  return tokens
}

/** Appends `incoming` to `existing`, dropping case/scheme-insensitive duplicates (first occurrence wins). */
export function mergeOrigins(existing: readonly string[], incoming: readonly string[]): string[] {
  const seen = new Set<string>()
  const merged: string[] = []
  for (const raw of [...existing, ...incoming]) {
    const trimmed = raw.trim()
    if (!trimmed) continue
    const { key } = normalizeOrigin(trimmed)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(trimmed)
  }
  return merged
}

export function toOriginTokens(values: readonly string[]): OriginToken[] {
  return values.map(raw => ({ raw, ...normalizeOrigin(raw) }))
}

export function summarizeOrigins(values: readonly string[]): OriginSummary {
  const invalidTokens = toOriginTokens(values).filter(token => !token.valid).map(token => token.raw)
  return { total: values.length, invalid: invalidTokens.length, invalidTokens }
}

/** "12 origins · 1 invalid" */
export function formatOriginCount(total: number, invalid: number): string {
  return [
    `${total.toLocaleString('en-US')} ${total === 1 ? 'origin' : 'origins'}`,
    invalid > 0 ? `${invalid.toLocaleString('en-US')} invalid` : '',
  ].filter(Boolean).join(' · ')
}

/**
 * Applies a keystroke/paste to the pending draft. Separators (new line, comma)
 * commit every segment; a typed trailing space commits only when the draft is
 * already a valid origin, so multi-word typos are never shredded mid-typing.
 */
export function applyOriginDraft(values: readonly string[], draft: string): { values: string[]; draft: string } {
  if (SEPARATOR_RE.test(draft)) return { values: mergeOrigins(values, tokenizeOrigins(draft)), draft: '' }
  if (/\s$/.test(draft) && draft.trim() && normalizeOrigin(draft).valid) {
    return { values: mergeOrigins(values, [draft.trim()]), draft: '' }
  }
  return { values: [...values], draft }
}

/** Commits whatever is pending (Enter, blur, or the text-mode toggle). */
export function commitOriginDraft(values: readonly string[], draft: string): string[] {
  return draft.trim() ? mergeOrigins(values, tokenizeOrigins(draft)) : [...values]
}

interface OriginChipInputProps {
  values: readonly string[]
  onChange: (values: string[]) => void
  label?: string
  /** Form field name for the active editor (chip draft textarea or the text-mode textarea). */
  name?: string
  placeholder?: string
  disabled?: boolean
  /** Fires when the user starts editing so callers can hide stale server errors. */
  onEdit?: () => void
}

export function OriginChipInput({
  values,
  onChange,
  label = 'Seed origins',
  name = 'seeds',
  placeholder = 'https://app.example.com',
  disabled = false,
  onEdit,
}: OriginChipInputProps) {
  const id = useId()
  const draftRef = useRef<HTMLTextAreaElement | null>(null)
  const [draft, setDraft] = useState('')
  const [textMode, setTextMode] = useState(false)
  const [text, setText] = useState('')

  const tokens = toOriginTokens(values)
  const summary = summarizeOrigins(values)
  const helpId = `${id}-help`
  const errorId = `${id}-error`

  function commitDraft() {
    if (!draft.trim()) return
    onChange(commitOriginDraft(values, draft))
    setDraft('')
  }

  function removeAt(index: number) {
    onChange(values.filter((_, i) => i !== index))
    draftRef.current?.focus()
  }

  function toggleTextMode() {
    if (textMode) {
      onChange(mergeOrigins([], tokenizeOrigins(text)))
      setTextMode(false)
      requestAnimationFrame(() => draftRef.current?.focus())
      return
    }
    const committed = commitOriginDraft(values, draft)
    if (committed.length !== values.length) onChange(committed)
    setDraft('')
    setText(committed.join('\n'))
    setTextMode(true)
  }

  return (
    <div className="grid min-w-0 gap-1.5" data-slot="origin-chip-input">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <span className="flex min-w-0 items-baseline gap-1.5 text-[12px] font-medium text-fg-muted">
          <label htmlFor={id}>{label}</label>
          {summary.total > 0 && (
            <>
              <span aria-hidden="true" className="text-fg-faint">·</span>
              <span
                className={cn('tabular-nums font-normal', summary.invalid > 0 ? 'text-danger' : 'text-fg-subtle')}
                data-slot="seed-count"
                aria-live="polite"
              >
                {formatOriginCount(summary.total, summary.invalid)}
              </span>
            </>
          )}
        </span>
        <button
          type="button"
          className="h-auto cursor-pointer whitespace-normal rounded-sm border-0 bg-transparent px-1 py-0.5 text-[11.5px] font-medium text-accent shadow-none hover:bg-transparent hover:underline disabled:cursor-default"
          aria-pressed={textMode}
          disabled={disabled}
          onClick={toggleTextMode}
        >
          {textMode ? 'Edit as chips' : 'Edit as text'}
        </button>
      </div>

      {textMode ? (
        <textarea
          id={id}
          data-slot="textarea"
          className="max-h-[168px] min-h-[76px] w-full min-w-0 font-mono text-[12px]"
          name={name}
          rows={Math.min(8, Math.max(3, values.length))}
          value={text}
          disabled={disabled}
          aria-invalid={summary.invalid > 0 ? true : undefined}
          aria-describedby={[helpId, summary.invalid > 0 ? errorId : ''].filter(Boolean).join(' ')}
          placeholder={placeholder}
          onChange={event => {
            const next = event.target.value
            setText(next)
            onEdit?.()
            onChange(mergeOrigins([], tokenizeOrigins(next)))
          }}
        />
      ) : (
        <div
          className={cn(
            'flex max-h-[148px] min-h-[34px] w-full min-w-0 cursor-text flex-wrap content-start items-center gap-1 overflow-y-auto rounded-[6px] bg-panel p-1 shadow-[var(--shadow-sm)] transition-shadow',
            'focus-within:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]',
            summary.invalid > 0 && 'shadow-[0_0_0_1px_color-mix(in_srgb,var(--danger)_45%,transparent)]',
            disabled && 'cursor-default opacity-60',
          )}
          data-slot="origin-chip-field"
          onClick={event => {
            if (event.target === event.currentTarget) draftRef.current?.focus()
          }}
        >
          <ul className="contents" aria-label={`${label} entered`}>
            {tokens.map((token, index) => (
              <li
                key={`${token.key}-${index}`}
                data-slot="origin-chip"
                data-valid={token.valid ? 'true' : 'false'}
                title={token.valid ? token.raw : `Not a valid http(s) origin: ${token.raw}`}
                className={cn(
                  'inline-flex min-h-[22px] min-w-0 max-w-full items-center gap-1 rounded-[5px] border py-px pl-1.5 pr-0.5 font-mono text-[11.5px] leading-[18px]',
                  token.valid
                    ? 'border-line-2 bg-sunk text-fg'
                    : 'border-danger/45 bg-danger-soft text-danger',
                )}
              >
                {!token.valid && <Icon name="alert" size={11} className="flex-none" />}
                <span className="min-w-0 truncate">{token.raw}</span>
                <button
                  type="button"
                  className="inline-flex size-4 h-4 flex-none cursor-pointer items-center justify-center whitespace-normal rounded-[3px] border-0 bg-transparent p-0 text-current opacity-70 shadow-none hover:bg-hover hover:opacity-100"
                  aria-label={`Remove ${token.raw}`}
                  disabled={disabled}
                  onClick={() => removeAt(index)}
                >
                  <Icon name="close" size={10} />
                </button>
              </li>
            ))}
          </ul>
          <textarea
            ref={draftRef}
            id={id}
            name={name}
            rows={1}
            value={draft}
            disabled={disabled}
            placeholder={values.length === 0 ? placeholder : 'Add origin…'}
            aria-invalid={summary.invalid > 0 ? true : undefined}
            aria-describedby={[helpId, summary.invalid > 0 ? errorId : ''].filter(Boolean).join(' ')}
            className="h-[22px] min-h-0 min-w-[14ch] flex-1 resize-none overflow-hidden rounded-none border-0 bg-transparent px-1 py-0 font-mono text-[12px] leading-[22px] shadow-none outline-none focus:shadow-none"
            onChange={event => {
              onEdit?.()
              const next = applyOriginDraft(values, event.target.value)
              if (next.values.length !== values.length) onChange(next.values)
              setDraft(next.draft)
            }}
            onKeyDown={event => {
              if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault()
                commitDraft()
                return
              }
              if (event.key === 'Backspace' && draft === '' && values.length > 0) {
                event.preventDefault()
                const last = values[values.length - 1]!
                onChange(values.slice(0, -1))
                setDraft(last)
              }
            }}
            onBlur={commitDraft}
          />
        </div>
      )}

      <span id={helpId} className="text-[11.5px] font-normal text-fg-subtle">
        {textMode
          ? 'One origin per line (commas and spaces also split).'
          : 'Enter, comma, or a new line adds an origin · Backspace edits the last one.'}
      </span>
      {summary.invalid > 0 && (
        <span id={errorId} className="form-error text-[11.5px] font-normal [overflow-wrap:anywhere]" data-slot="seed-invalid">
          Not a valid host or origin: {summary.invalidTokens.slice(0, 5).join(', ')}
          {summary.invalid > 5 ? ` and ${summary.invalid - 5} more` : ''}
        </span>
      )}
    </div>
  )
}
