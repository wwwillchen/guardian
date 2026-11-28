// Structured proof viewers (code-split chunk; loaded lazily by the Finding inspector, Report,
// Queue reading view and Exchanges drawer so the run route bundle stays inside its budget).
//
//   ReceiptView         Control | Variant comparison table + collapsible structured JSON tree
//   ControlVariantCells two crisp mono cells for the Finding inspector verdict card
//   CompositeDagRail    vertical timeline rail for multi-hop composite proof chains
//   ExchangeDetailTabs  Request / Response / Timing / Raw tabs + "Compare with…" exchange diff
//
// Display-only: nothing here decides a verdict. Sensitive headers and credential-shaped values
// are redacted by default (display and clipboard alike); raw values need an explicit Reveal.
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useFullExchange, useRunModel } from '../data.tsx'
import { fmtFullDateTime, fmtN, fmtRel, host, prettyBody } from '../format.ts'
import { CopyMorphIcon, useCopyFlash } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { FullExchange } from '../data.tsx'
import type { Exchange } from '../model.ts'
import { cn, httpCodeClass, runBtn, RW } from '../tw.ts'
import { CompositeProofDagCard, EDGE_KIND_LABEL, extractCompositeProofSummary } from './findings-inspector.tsx'
import type { CompositeDagEdgeSummary, CompositeDagSummary } from './findings-inspector.tsx'

// ---------------------------------------------------------------- redaction (pure)

export const REDACTED = '[redacted]'

/** Headers whose values are credentials or session material; redacted unless explicitly revealed. */
export const SENSITIVE_HEADER_NAMES: ReadonlySet<string> = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'api-key', 'x-auth-token',
  'x-access-token', 'x-csrf-token', 'x-xsrf-token', 'x-amz-security-token', 'x-session-token', 'x-refresh-token',
])
const SENSITIVE_KEY_RE = /(?:^|[_-])(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|session[_-]?id|credential|private[_-]?key)(?:$|[_-])/i
const SECRET_VALUE_RE = /\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}|\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g

export function isSensitiveHeader(name: string): boolean {
  const k = name.trim().toLowerCase()
  return SENSITIVE_HEADER_NAMES.has(k) || SENSITIVE_KEY_RE.test(k)
}

/** Mask credential-shaped substrings (bearer/basic tokens, JWTs) inside free text. */
export function redactSecretText(text: string): string {
  return text.replace(SECRET_VALUE_RE, m => {
    const sp = m.search(/\s/)
    return sp > 0 ? m.slice(0, sp) + ' ' + REDACTED : REDACTED
  })
}

/** Header map with sensitive values replaced (or kept verbatim when `reveal`); never throws on junk. */
export function redactHeaders(headers: unknown, reveal = false): Record<string, string> {
  const out: Record<string, string> = {}
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return out
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    const val = v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v) ?? ''
    out[k] = reveal ? val : isSensitiveHeader(k) ? REDACTED : redactSecretText(val)
  }
  return out
}

/**
 * Deep copy safe for clipboard export or display: sensitive keys become `[redacted]`, secret-shaped
 * strings are masked, cycles and depth are bounded. Accepts any shape (null, primitives, arrays).
 */
export function redactForClipboard(value: unknown, depth = 0, seen: WeakSet<object> = new WeakSet()): unknown {
  if (value == null || typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'string') return redactSecretText(value)
  if (typeof value !== 'object') return String(value)
  if (seen.has(value) || depth > 12) return '[…]'
  seen.add(value)
  if (Array.isArray(value)) return value.slice(0, 500).map(v => redactForClipboard(v, depth + 1, seen))
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = isSensitiveHeader(k) && v != null && typeof v !== 'object' ? REDACTED : redactForClipboard(v, depth + 1, seen)
  }
  return out
}

/** Middle-truncate long strings so both the prefix and the distinguishing tail stay visible. */
export function middleTruncate(s: string, max = 64): string {
  if (s.length <= max) return s
  const keep = Math.max(2, max - 1)
  const head = Math.ceil(keep / 2)
  return s.slice(0, head) + '…' + s.slice(s.length - (keep - head))
}

// ---------------------------------------------------------------- receipt normalization (pure)

export interface ReceiptSide {
  status: number | null
  bytes: number | null
  digest: string | null
  timingMs: number | null
  mediaType: string | null
  headers: Record<string, string>
}

export interface ReceiptComparisonRow { key: string; label: string; control: string; variant: string; differs: boolean; mono?: boolean }

export interface ReceiptComparison {
  /** False when neither a control/variant step pair nor two receipt exchanges were recorded. */
  paired: boolean
  control: ReceiptSide
  variant: ReceiptSide
  rows: ReceiptComparisonRow[]
  /** Redacted, structured receipt payload for the JSON tree (null when nothing was recorded). */
  tree: unknown
}

export interface ReceiptExchangeLike {
  status?: unknown
  durationMs?: unknown
  bodySha256?: unknown
  mediaType?: unknown
  bodyPreview?: unknown
  respHeaders?: unknown
}

const KEY_HEADERS = ['content-length', 'location', 'cache-control', 'set-cookie', 'www-authenticate', 'access-control-allow-origin', 'x-frame-options']
const CONTROL_ROLE_RE = /control|baseline|benign|negative|clean/i
const VARIANT_ROLE_RE = /variant|attack|trigger|exploit|probe|positive|mutat|test/i
const EMPTY_SIDE: ReceiptSide = { status: null, bytes: null, digest: null, timingMs: null, mediaType: null, headers: {} }

const rec = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null)
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const strOrNull = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null)

function sideFromStep(step: Record<string, unknown> | null): Partial<ReceiptSide> {
  if (!step) return {}
  return { status: num(step.status), bytes: num(step.bodyLen), mediaType: strOrNull(step.mediaType) }
}

function sideFromExchange(x: ReceiptExchangeLike | null | undefined): Partial<ReceiptSide> {
  if (!x) return {}
  const headers = redactHeaders(x.respHeaders)
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  const len = Number(lower['content-length'])
  return {
    status: num(x.status),
    bytes: Number.isFinite(len) && lower['content-length'] !== undefined ? len : null,
    digest: strOrNull(x.bodySha256),
    timingMs: num(x.durationMs),
    mediaType: strOrNull(x.mediaType),
    headers: lower,
  }
}

function mergeSide(primary: Partial<ReceiptSide>, secondary: Partial<ReceiptSide>): ReceiptSide {
  return {
    status: primary.status ?? secondary.status ?? null,
    bytes: primary.bytes ?? secondary.bytes ?? null,
    digest: primary.digest ?? secondary.digest ?? null,
    timingMs: primary.timingMs ?? secondary.timingMs ?? null,
    mediaType: primary.mediaType ?? secondary.mediaType ?? null,
    headers: { ...(secondary.headers ?? {}), ...(primary.headers ?? {}) },
  }
}

/** Receipt exchange ids from a proof receipt envelope (`{ receipt: { exchangeIds } }`), if any. */
export function receiptExchangeIds(proofReceipt: unknown): string[] {
  const ids = rec(rec(proofReceipt)?.receipt)?.exchangeIds
  return Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string' && x.length > 0) : []
}

const fmtStatus = (s: number | null) => (s == null ? '—' : String(s))
const fmtBytes = (b: number | null) => (b == null ? '—' : fmtN(b) + ' B')
const fmtMs = (ms: number | null) => (ms == null ? '—' : fmtN(Math.round(ms)) + ' ms')

/** One-line `status · bytes · timing` cell text with em-dash placeholders (never null/undefined). */
export function receiptCellText(side: ReceiptSide): string {
  return [fmtStatus(side.status), fmtBytes(side.bytes), fmtMs(side.timingMs)].join(' · ')
}

/**
 * Defensive control-vs-variant extraction from arbitrary `lastVerificationDiff` / replay receipt
 * shapes. Step roles decide the pair; receipt exchanges (first = control, second = variant) fill in
 * digest, timing and key headers. Unexpected shapes degrade to an unpaired, placeholder comparison.
 */
export function normalizeReceiptComparison(input: {
  diff?: unknown
  proofReceipt?: unknown
  control?: ReceiptExchangeLike | null
  variant?: ReceiptExchangeLike | null
}): ReceiptComparison {
  const diff = rec(input.diff)
  const steps = Array.isArray(diff?.stepStatuses) ? diff!.stepStatuses.map(rec).filter((s): s is Record<string, unknown> => Boolean(s)) : []
  const role = (s: Record<string, unknown>) => (typeof s.role === 'string' ? s.role : '')
  const controlStep = steps.find(s => CONTROL_ROLE_RE.test(role(s))) ?? null
  const variantStep = [...steps].reverse().find(s => s !== controlStep && VARIANT_ROLE_RE.test(role(s)))
    ?? [...steps].reverse().find(s => s !== controlStep) ?? null
  const paired = Boolean((controlStep && variantStep) || (input.control && input.variant))
  const control = paired ? mergeSide(sideFromStep(controlStep), sideFromExchange(input.control)) : EMPTY_SIDE
  const variant = paired ? mergeSide(sideFromStep(variantStep), sideFromExchange(input.variant)) : EMPTY_SIDE
  const row = (key: string, label: string, c: string, v: string, mono = true): ReceiptComparisonRow =>
    ({ key, label, control: c, variant: v, differs: c !== v && (c !== '—' || v !== '—'), mono })
  const rows: ReceiptComparisonRow[] = [
    row('status', 'Status', fmtStatus(control.status), fmtStatus(variant.status)),
    row('bytes', 'Bytes', fmtBytes(control.bytes), fmtBytes(variant.bytes)),
    row('digest', 'Digest', control.digest ? middleTruncate(control.digest, 20) : '—', variant.digest ? middleTruncate(variant.digest, 20) : '—'),
    row('timing', 'Timing', fmtMs(control.timingMs), fmtMs(variant.timingMs)),
    row('media', 'Media type', control.mediaType ?? '—', variant.mediaType ?? '—'),
  ]
  for (const h of KEY_HEADERS) {
    const c = control.headers[h], v = variant.headers[h]
    if (c !== undefined || v !== undefined) rows.push(row('h:' + h, h, c || '—', v || '—'))
  }
  const proof = rec(input.proofReceipt)
  const treeSrc: Record<string, unknown> = {}
  if (proof?.verification !== undefined) treeSrc.verification = proof.verification
  if (proof?.receipt !== undefined) treeSrc.receipt = proof.receipt
  if (proof?.compositeVerification !== undefined) treeSrc.compositeVerification = proof.compositeVerification
  if (input.diff !== undefined && input.diff !== null) treeSrc.lastVerificationDiff = input.diff
  if (!Object.keys(treeSrc).length && input.proofReceipt != null) treeSrc.proofReceipt = input.proofReceipt
  return { paired, control, variant, rows, tree: Object.keys(treeSrc).length ? redactForClipboard(treeSrc) : null }
}

// ---------------------------------------------------------------- exchange diff (pure)

export interface ExchangeDiffInput {
  method?: string | null
  pathAndQuery?: string | null
  status?: number | null
  durationMs?: number | null
  mediaType?: string | null
  body?: string | null
  bodyPreview?: string | null
  bodySha256?: string | null
  respHeaders?: unknown
}

export interface ExchangeDiff {
  rows: ReceiptComparisonRow[]
  /** Line-aligned body preview diff (bounded); `same` marks identical lines. */
  body: Array<{ a: string; b: string; same: boolean }>
}

const BODY_DIFF_LINES = 40

/** Side-by-side control vs variant diff of two exchanges (headers redacted unless `reveal`). */
export function diffExchanges(a: ExchangeDiffInput | null | undefined, b: ExchangeDiffInput | null | undefined, reveal = false): ExchangeDiff {
  const row = (key: string, label: string, x: string, y: string, mono = true): ReceiptComparisonRow =>
    ({ key, label, control: x, variant: y, differs: x !== y, mono })
  const body = (x: ExchangeDiffInput | null | undefined) => (typeof x?.body === 'string' ? x.body : typeof x?.bodyPreview === 'string' ? x.bodyPreview : '')
  const ba = body(a), bb = body(b)
  const rows: ReceiptComparisonRow[] = [
    row('request', 'Request', [a?.method, a?.pathAndQuery].filter(Boolean).join(' ') || '—', [b?.method, b?.pathAndQuery].filter(Boolean).join(' ') || '—'),
    row('status', 'Status', fmtStatus(num(a?.status)), fmtStatus(num(b?.status))),
    row('bytes', 'Body chars', fmtN(ba.length), fmtN(bb.length)),
    row('timing', 'Timing', fmtMs(num(a?.durationMs)), fmtMs(num(b?.durationMs))),
    row('media', 'Media type', strOrNull(a?.mediaType) ?? '—', strOrNull(b?.mediaType) ?? '—'),
    row('digest', 'Digest', middleTruncate(strOrNull(a?.bodySha256) ?? '—', 20), middleTruncate(strOrNull(b?.bodySha256) ?? '—', 20)),
  ]
  const ha = lowerKeys(redactHeaders(a?.respHeaders, reveal)), hb = lowerKeys(redactHeaders(b?.respHeaders, reveal))
  for (const k of [...new Set([...Object.keys(ha), ...Object.keys(hb)])].sort()) rows.push(row('h:' + k, k, ha[k] ?? '—', hb[k] ?? '—'))
  const la = (reveal ? ba : redactSecretText(ba)).split('\n').slice(0, BODY_DIFF_LINES)
  const lb = (reveal ? bb : redactSecretText(bb)).split('\n').slice(0, BODY_DIFF_LINES)
  const n = Math.max(la.length, lb.length)
  const lines = Array.from({ length: n }, (_, i) => ({ a: la[i] ?? '', b: lb[i] ?? '', same: (la[i] ?? '') === (lb[i] ?? '') }))
  return { rows, body: lines }
}

const lowerKeys = (h: Record<string, string>) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]))

// ---------------------------------------------------------------- shared UI bits

function LeafCopy({ value, label }: { value: string; label: string }) {
  const [copied, flash] = useCopyFlash()
  return <button
    type="button"
    className="inline-flex h-[18px] w-[18px] flex-none cursor-pointer items-center justify-center rounded-[4px] border-0 bg-transparent p-0 text-fg-faint shadow-none hover:bg-hover hover:text-fg"
    aria-label={'Copy ' + label}
    title={copied ? 'Copied' : 'Copy value'}
    data-slot="json-leaf-copy"
    onClick={e => { e.stopPropagation(); void navigator.clipboard?.writeText(value).then(flash, () => undefined) }}
  >
    <CopyMorphIcon copied={copied} size={12} />
  </button>
}

const CMP_CELL = 'min-w-0 px-2.5 py-[5px] font-mono text-[11.5px] leading-[17px] [overflow-wrap:anywhere]'

/** Two-column Control | Variant table; differing rows are tinted `bg-warn-soft`. */
function ComparisonTable({ rows, slot, labels = ['Control', 'Variant'] }: { rows: readonly ReceiptComparisonRow[]; slot: string; labels?: [string, string] }) {
  return <div data-slot={slot} className="mb-2.5 min-w-0 overflow-hidden rounded-lg border border-line text-[12px]" role="table" aria-label={labels.join(' vs ')}>
    <div className="grid grid-cols-[88px_minmax(0,1fr)_minmax(0,1fr)] border-b border-line bg-sunk text-[11.5px] font-medium text-fg-subtle" role="row">
      <span className="px-2.5 py-[5px]" role="columnheader">Field</span>
      <span className="border-l border-line px-2.5 py-[5px]" role="columnheader">{labels[0]}</span>
      <span className="border-l border-line px-2.5 py-[5px]" role="columnheader">{labels[1]}</span>
    </div>
    {rows.map(r => <div key={r.key} role="row" data-differs={r.differs || undefined}
      className={cn('grid grid-cols-[88px_minmax(0,1fr)_minmax(0,1fr)] border-b border-line last:border-b-0', r.differs && 'bg-warn-soft')}>
      <span className="min-w-0 truncate px-2.5 py-[5px] text-fg-subtle" title={r.label} role="cell">{r.label}</span>
      <span className={cn(CMP_CELL, 'border-l border-line', r.differs ? 'text-fg' : 'text-fg-muted')} role="cell" data-cell="control">{r.control}</span>
      <span className={cn(CMP_CELL, 'border-l border-line', r.differs ? 'text-fg' : 'text-fg-muted')} role="cell" data-cell="variant">{r.variant}</span>
    </div>)}
  </div>
}

// ---------------------------------------------------------------- JSON tree

const MAX_CHILDREN = 200

function JsonString({ value }: { value: string }) {
  const [open, setOpen] = useState(false)
  if (value.length <= 64) return <span className="text-fg [overflow-wrap:anywhere]">&quot;{value}&quot;</span>
  return <button
    type="button"
    data-slot="json-truncated"
    data-expanded={open || undefined}
    className="h-auto min-w-0 cursor-pointer whitespace-normal rounded-[3px] border-0 bg-transparent p-0 text-left font-mono text-[11.5px] text-fg shadow-none [overflow-wrap:anywhere] hover:bg-hover"
    title={open ? 'Collapse value' : `Show all ${fmtN(value.length)} characters`}
    onClick={() => setOpen(o => !o)}
  >&quot;{open ? value : middleTruncate(value, 64)}&quot;</button>
}

function JsonLeaf({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span data-slot="json-null" className="inline-flex h-4 items-center rounded-[4px] bg-sunk px-1.5 font-sans text-[11px] text-fg-subtle shadow-[inset_0_0_0_1px_var(--line)]" title="null">—</span>
  }
  if (typeof value === 'number') return <span className="tabular-nums text-fg">{String(value)}</span>
  if (typeof value === 'boolean') return <span className="text-fg">{String(value)}</span>
  return <JsonString value={String(value)} />
}

function JsonNode({ name, value, depth }: { name: string | null; value: unknown; depth: number }) {
  const isObj = value !== null && typeof value === 'object'
  const [open, setOpen] = useState(depth < 2)
  const keyEl = name != null && <span className="flex-none text-fg-subtle">{name}:</span>
  if (!isObj) {
    return <div className="group flex min-w-0 items-start gap-1.5 py-px" data-slot="json-leaf">
      {keyEl}<span className="min-w-0 flex-1"><JsonLeaf value={value} /></span>
      <LeafCopy value={value == null ? 'null' : String(value)} label={name ?? 'value'} />
    </div>
  }
  const entries: [string, unknown][] = Array.isArray(value) ? value.map((v, i) => [String(i), v]) : Object.entries(value as Record<string, unknown>)
  const summary = Array.isArray(value) ? `[${entries.length}]` : `{${entries.length}}`
  return <div className="min-w-0">
    <button
      type="button"
      className="flex h-auto min-w-0 cursor-pointer items-center gap-1 whitespace-normal rounded-[3px] border-0 bg-transparent p-0 py-px text-left font-mono text-[11.5px] shadow-none hover:bg-hover"
      aria-expanded={open}
      onClick={() => setOpen(o => !o)}
    >
      <Icon name="chev" className={cn('flex-none text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', !open && '-rotate-90')} />
      {name != null && <span className="text-fg-subtle">{name}:</span>}
      <span className="text-fg-faint">{summary}</span>
    </button>
    {open && <div className="ml-[5px] min-w-0 border-l border-line pl-2.5">
      {entries.slice(0, MAX_CHILDREN).map(([k, v]) => <JsonNode key={k} name={k} value={v} depth={depth + 1} />)}
      {entries.length > MAX_CHILDREN && <div className="py-px text-fg-subtle">… {fmtN(entries.length - MAX_CHILDREN)} more</div>}
    </div>}
  </div>
}

/** Collapsible structured JSON tree (keys subtle, numbers tabular, null as an em-dash pill, long strings middle-truncated). */
export function JsonTree({ value, title = 'Structured receipt' }: { value: unknown; title?: string }) {
  const [open, setOpen] = useState(false)
  return <div data-slot="json-tree" className="min-w-0 rounded-lg border border-line bg-sunk/60">
    <button
      type="button"
      className="flex h-8 w-full cursor-pointer items-center gap-1.5 rounded-lg border-0 bg-transparent px-2.5 text-left text-[12px] font-medium text-fg-muted shadow-none hover:bg-transparent hover:text-fg"
      aria-expanded={open}
      onClick={() => setOpen(o => !o)}
    >
      <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', !open && '-rotate-90')} />
      {title}<span className="ml-auto text-[11px] font-normal text-fg-subtle">redacted</span>
    </button>
    {open && <div className="min-w-0 border-t border-line px-2.5 py-2 font-mono text-[11.5px] leading-[18px]">
      <JsonNode name={null} value={value} depth={0} />
    </div>}
  </div>
}

// ---------------------------------------------------------------- ReceiptView

function useReceiptComparison(diff: unknown, proofReceipt: unknown, exchangeIds: readonly string[]): ReceiptComparison {
  const model = useRunModel()
  const fromReceipt = receiptExchangeIds(proofReceipt)
  const ids = fromReceipt.length >= 2 ? fromReceipt : exchangeIds
  const [cId, vId] = ids.length >= 2 ? [ids[0]!, ids[1]!] : ['', '']
  const cFull = useFullExchange(cId, Boolean(cId))
  const vFull = useFullExchange(vId, Boolean(vId))
  const control: ReceiptExchangeLike | null = cId ? (cFull ?? model.exchangeById.get(cId) ?? null) : null
  const variant: ReceiptExchangeLike | null = vId ? (vFull ?? model.exchangeById.get(vId) ?? null) : null
  return useMemo(() => normalizeReceiptComparison({ diff, proofReceipt, control, variant }), [diff, proofReceipt, control, variant])
}

/** Structured receipt diff: Control | Variant table (differences tinted) and a redacted JSON tree. */
export function ReceiptView({ diff, proofReceipt, exchangeIds = [] }: { diff?: unknown; proofReceipt?: unknown; exchangeIds?: readonly string[] }) {
  const cmp = useReceiptComparison(diff, proofReceipt, exchangeIds)
  return <div data-slot="receipt-view" className="mb-3 min-w-0">
    {cmp.paired
      ? <ComparisonTable rows={cmp.rows} slot="receipt-table" />
      : <p className="text-fg-subtle!">No control vs. variant pair was recorded for this replay.</p>}
    {cmp.tree != null && <JsonTree value={cmp.tree} />}
  </div>
}

/** Verdict-card outcome: control and variant as two `status · bytes · timing` mono cells. */
export function ControlVariantCells({ diff, proofReceipt, exchangeIds = [] }: { diff?: unknown; proofReceipt?: unknown; exchangeIds?: readonly string[] }) {
  const cmp = useReceiptComparison(diff, proofReceipt, exchangeIds)
  return <ControlVariantGrid control={receiptCellText(cmp.control)} variant={receiptCellText(cmp.variant)} />
}

/** Static two-cell grid (also the Suspense fallback, so the lazy swap never shifts layout). */
export function ControlVariantGrid({ control, variant }: { control: string; variant: string }) {
  return <div data-slot="control-variant" className="grid h-[44px] min-w-0 grid-cols-2 gap-1.5">
    {([['Control', control], ['Variant', variant]] as const).map(([l, v]) => <div key={l} className="min-w-0 rounded-[6px] bg-sunk px-2 py-1.5 shadow-[inset_0_0_0_1px_var(--line)]">
      <div className="text-[11px] leading-[15px] text-fg-subtle">{l}</div>
      <div className="truncate font-mono text-[11.5px] leading-[17px] tabular-nums text-fg" title={v} data-cell={l.toLowerCase()}>{v}</div>
    </div>)}
  </div>
}

// ---------------------------------------------------------------- CompositeDagRail

const RAIL_VISIBLE = 4

function EdgeLabel({ edge }: { edge: CompositeDagEdgeSummary }) {
  const mark = edge.verified === true ? ' ✓' : edge.verified === false ? ' !' : ''
  return <span className={cn('inline-flex min-w-0 max-w-full items-center gap-1 text-[11px]', edge.verified === false ? 'text-warn' : 'text-fg-subtle')} data-slot="dag-edge">
    <span className="flex-none">{(EDGE_KIND_LABEL[edge.kind] ?? edge.kind) + mark}</span>
    {edge.capabilityHandles.slice(0, 2).map(h => <span key={h} className="min-w-0 truncate font-mono text-[10.5px] text-fg-muted" title={h}>{h}</span>)}
  </span>
}

/** Vertical timeline rail for a multi-hop composite proof: numbered nodes, inline edge labels, terminal/patch markers. */
export function CompositeDagRail({ summary }: { summary: CompositeDagSummary }) {
  const [all, setAll] = useState(false)
  const incoming = useMemo(() => {
    const m = new Map<string, CompositeDagEdgeSummary[]>()
    for (const e of summary.edges) m.set(e.toHopId, [...(m.get(e.toHopId) ?? []), e])
    return m
  }, [summary.edges])
  const hidden = Math.max(0, summary.hops.length - RAIL_VISIBLE)
  const hops = all ? summary.hops : summary.hops.slice(0, RAIL_VISIBLE)
  return <div data-slot="dag-rail" className="min-w-0">
    <ol className="m-0 min-w-0 list-none p-0">
      {hops.map((hop, i) => {
        const last = i === hops.length - 1
        const target = [hop.method, (hop.origin ? host(hop.origin) : '') + (hop.pathAndQuery ?? '')].filter(Boolean).join(' ')
        const edges = incoming.get(hop.hopId) ?? []
        return <li key={hop.hopId} data-slot="dag-hop" data-hop-id={hop.hopId} className="relative grid min-w-0 grid-cols-[18px_minmax(0,1fr)] gap-x-2.5 pb-3 last:pb-0">
          {!last && <span aria-hidden="true" className="absolute bottom-0 left-[8.5px] top-[18px] w-px bg-line-2" />}
          <span className={cn(
            'relative z-[1] grid size-[18px] place-items-center rounded-full text-[10.5px] font-semibold tabular-nums',
            hop.patchBrokeHere ? 'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]'
              : hop.isTerminal ? 'bg-accent-soft text-accent shadow-[inset_0_0_0_1px_var(--accent-line)]'
                : 'bg-panel text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]',
          )}>{hop.order}</span>
          <div className="min-w-0 text-[12px] leading-[18px]">
            {edges.length > 0 && <div className="-mt-0.5 mb-0.5 flex min-w-0 flex-wrap gap-x-2">{edges.map((e, k) => <EdgeLabel key={e.fromHopId + k} edge={e} />)}</div>}
            <div className="flex min-w-0 flex-wrap items-center gap-x-1.5">
              <span className="font-medium text-fg">{['Hop ' + hop.order, hop.surface, hop.actor].filter(Boolean).join(' · ')}</span>
              {hop.isTerminal && <span className="text-[11px] font-medium text-accent">Terminal</span>}
              {hop.patchBrokeHere && <span className="text-[11px] font-medium text-warn">Patch broke here</span>}
            </div>
            {target && <div className="truncate font-mono text-[11.5px] text-fg-muted" title={target}>{middleTruncate(target, 56)}</div>}
            {hop.claimedDelta && <div className="text-fg-subtle [overflow-wrap:anywhere]">{hop.claimedDelta}</div>}
          </div>
        </li>
      })}
    </ol>
    {hidden > 0 && <button type="button" data-slot="dag-more" className={cn(runBtn({ variant: 'link', size: 'none' }), 'ml-[28px] mt-1.5 text-[12px]')} aria-expanded={all} onClick={() => setAll(v => !v)}>
      {all ? 'Show fewer hops' : `Show ${hidden} more ${hidden === 1 ? 'hop' : 'hops'}`}
    </button>}
  </div>
}

/** Composite chain card + rail straight from a replay spec row (for views that cannot import the inspector). */
export function ChainProof({ replay, retests, compact }: {
  replay: Parameters<typeof extractCompositeProofSummary>[0]
  retests?: Parameters<typeof extractCompositeProofSummary>[1]
  compact?: boolean
}) {
  const summary = useMemo(() => extractCompositeProofSummary(replay, retests), [replay, retests])
  if (!summary) return null
  return <CompositeProofDagCard summary={summary} compact={compact}><CompositeDagRail summary={summary} /></CompositeProofDagCard>
}

// ---------------------------------------------------------------- exchange detail tabs

type XTab = 'request' | 'response' | 'timing' | 'raw'
const XTABS: [XTab, string][] = [['request', 'Request'], ['response', 'Response'], ['timing', 'Timing'], ['raw', 'Raw']]
const BASELINE: [string, string][] = [
  ['strict-transport-security', 'HSTS'], ['content-security-policy', 'CSP'], ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'Frame options'], ['referrer-policy', 'Referrer policy'],
]
const BODY_CAP = 12000
/** Response headers that matter for security review (marked with a dot in the table). */
const SECURITY_HEADERS: ReadonlySet<string> = new Set([
  'strict-transport-security', 'content-security-policy', 'content-security-policy-report-only', 'x-content-type-options',
  'x-frame-options', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy', 'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-methods',
  'access-control-allow-headers', 'set-cookie', 'server', 'x-powered-by', 'via', 'www-authenticate',
])
const DOT = 'before:mb-px before:mr-1.5 before:inline-block before:size-[5px] before:rounded-full before:align-middle before:content-[""]'

function HeaderRows({ headers, flagged, reveal }: { headers: Record<string, string> | undefined; flagged: ReadonlySet<string>; reveal: boolean }) {
  const shown = redactHeaders(headers, reveal)
  const ks = Object.keys(shown)
  if (!ks.length) return <p className="text-fg-subtle!">None recorded</p>
  return <table className={cn(RW.hdrs, 'table-fixed font-mono text-[12px]')} data-slot="header-table"><tbody>{ks.map(k => {
    const lk = k.toLowerCase()
    const isFlag = flagged.has(lk)
    const masked = !reveal && isSensitiveHeader(lk)
    return <tr key={k}>
      <td className={cn('w-[40%] border-b border-line py-[3px] pr-2.5 align-top text-[11.5px] leading-[17px] [overflow-wrap:anywhere]', isFlag ? cn('bg-warn-soft font-medium text-warn before:bg-warn', DOT) : SECURITY_HEADERS.has(lk) ? cn('text-fg before:bg-fg-subtle', DOT) : 'text-fg-subtle')}>{k}</td>
      <td className={cn('border-b border-line py-[3px] align-top text-[11.5px] leading-[17px] text-fg-muted [overflow-wrap:anywhere]', isFlag && 'bg-warn-soft')} data-redacted={masked || undefined}>
        {masked ? <span className="font-sans text-fg-subtle">{REDACTED}</span> : shown[k]}
      </td>
    </tr>
  })}</tbody></table>
}

function RevealToggle({ reveal, onToggle, count }: { reveal: boolean; onToggle: () => void; count: number }) {
  if (!count) return null
  return <button type="button" data-slot="reveal-toggle" aria-pressed={reveal} className={cn(runBtn({ variant: 'ghost', size: 'xs' }), 'ml-auto')} onClick={onToggle}
    title={reveal ? 'Hide sensitive header values' : `Reveal ${count} sensitive header ${count === 1 ? 'value' : 'values'}`}>
    <Icon name="lock" size={12} />{reveal ? 'Hide' : 'Reveal'}
  </button>
}

const sensitiveCount = (h: Record<string, string> | undefined) => Object.keys(h ?? {}).filter(isSensitiveHeader).length

function SecurityHeaderChips({ resp, flagged }: { resp: Record<string, string>; flagged: ReadonlySet<string> }) {
  const keys = new Set(Object.keys(resp).map(k => k.toLowerCase()))
  return <div className="mb-2.5 flex flex-wrap gap-[5px]">{BASELINE.map(([h, l]) => {
    const has = keys.has(h)
    return <span key={h} className={cn('inline-flex h-[22px] items-center gap-1 rounded-[5px] pl-1.5 pr-2 text-[12px]',
      has ? 'text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]' : 'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]', flagged.has(h) && 'font-medium')}
      title={has ? h + ' present' : h + ' is absent'}>
      <Icon name={has ? 'check' : 'x'} size={12} className={has ? 'text-fg-subtle' : 'text-warn'} />{l}
    </span>
  })}</div>
}

function BodyBlock({ body }: { body: string }) {
  const [all, setAll] = useState(false)
  if (!body) return <p className="text-fg-subtle!">No body recorded</p>
  return <>
    <pre className={cn(RW.pre, 'max-h-[420px]')}>{all ? body : body.slice(0, BODY_CAP)}</pre>
    {body.length > BODY_CAP && !all && <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1')} onClick={() => setAll(true)}>Show all {fmtN(body.length)} characters</button>}
  </>
}

function SubHead({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return <h4 className="m-0 mb-1.5 mt-3 flex min-h-6 items-center gap-1.5 text-[11.5px] font-medium text-fg-subtle">{children}{right}</h4>
}

function TimingPanel({ x, base }: { x: { durationMs?: number | null; createdAt?: number | null }; base: number }) {
  const dur = typeof x.durationMs === 'number' ? x.durationMs : null
  const t = typeof x.createdAt === 'number' ? x.createdAt : null
  return <div data-slot="timing-panel" className="min-w-0">
    <div className="mb-2 mt-1 flex items-baseline gap-2"><span className="text-[18px] font-[550] tabular-nums text-fg">{dur == null ? '—' : fmtN(dur)}</span><span className="text-fg-subtle">ms total</span></div>
    <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-sunk"><i className="block h-full rounded-full bg-fg-subtle" style={{ width: dur == null ? 0 : '100%' }} /></div>
    <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-y-1 text-[12.5px]">
      <span className="text-fg-subtle">Recorded</span><span className="min-w-0 truncate tabular-nums text-fg">{t == null ? '—' : fmtFullDateTime(t)}</span>
      <span className="text-fg-subtle">Run offset</span><span className="font-mono text-[12px] tabular-nums text-fg">{t == null ? '—' : fmtRel(t, base)}</span>
    </div>
    <p className="mt-2.5 text-[12px]! text-fg-subtle!">The safety proxy records total round-trip time only; a per-phase breakdown (DNS, connect, TLS, first byte) was not captured for this exchange.</p>
  </div>
}

function rawText(x: FullExchange | Exchange, reveal: boolean): string {
  const full = x as Partial<FullExchange>
  const req = redactHeaders(full.reqHeaders, reveal)
  const resp = redactHeaders(full.respHeaders, reveal)
  const body = typeof full.body === 'string' ? full.body : x.bodyPreview ?? ''
  return [
    `${x.method} ${x.pathAndQuery} HTTP/1.1`, `Host: ${host(x.origin)}`, ...Object.entries(req).map(([k, v]) => `${k}: ${v}`), '',
    `HTTP/1.1 ${x.status}`, ...Object.entries(resp).map(([k, v]) => `${k}: ${v}`), '', reveal ? body : redactSecretText(body),
  ].join('\n')
}

function CompareWith({ self, candidates }: { self: FullExchange | Exchange; candidates: readonly Exchange[] }) {
  const [other, setOther] = useState('')
  const [reveal, setReveal] = useState(false)
  const full = useFullExchange(other, Boolean(other))
  const model = useRunModel()
  const b = other ? (full ?? model.exchangeById.get(other)) : undefined
  const d = useMemo(() => (b ? diffExchanges(self as ExchangeDiffInput, b as ExchangeDiffInput, reveal) : null), [self, b, reveal])
  return <div data-slot="exchange-compare" className="min-w-0">
    <SubHead right={d ? <RevealToggle reveal={reveal} onToggle={() => setReveal(r => !r)} count={sensitiveCount((b as Partial<FullExchange>)?.respHeaders) + sensitiveCount((self as Partial<FullExchange>).respHeaders)} /> : undefined}>Compare with…</SubHead>
    <select aria-label="Compare with exchange" className={cn(RW.fieldInput, 'mb-2 w-full')} value={other} onChange={e => setOther(e.target.value)}>
      <option value="">Pick a second exchange (variant)…</option>
      {candidates.map(c => <option key={c.id} value={c.id}>{c.method} {c.status} · {middleTruncate(c.pathAndQuery, 52)}</option>)}
    </select>
    {d && <>
      <ComparisonTable rows={d.rows} slot="exchange-diff" labels={['This exchange', 'Compared']} />
      <div data-slot="exchange-body-diff" className="mb-2.5 min-w-0 overflow-hidden rounded-lg border border-line font-mono text-[11.5px] leading-[17px]">
        {d.body.map((l, i) => <div key={i} className={cn('grid grid-cols-2', !l.same && 'bg-warn-soft')}>
          <span className="min-w-0 px-2 [overflow-wrap:anywhere] text-fg-muted">{l.a || ' '}</span>
          <span className="min-w-0 border-l border-line px-2 [overflow-wrap:anywhere] text-fg-muted">{l.b || ' '}</span>
        </div>)}
      </div>
    </>}
  </div>
}

/** Exchange drawer detail: Request / Response / Timing / Raw tabs, redacted headers, and a Compare with… diff. */
export function ExchangeDetailTabs({ x, full, flagged, candidates }: {
  x: FullExchange | Exchange
  full: FullExchange | undefined
  flagged: ReadonlySet<string>
  candidates: readonly Exchange[]
}) {
  const model = useRunModel()
  const [tab, setTab] = useState<XTab>('response')
  const [reveal, setReveal] = useState(false)
  const req = full?.reqHeaders ?? {}
  const resp = full?.respHeaders ?? {}
  const body = full ? prettyBody(full.body, full.mediaType) : prettyBody(x.bodyPreview, x.mediaType)
  const toggle = <RevealToggle reveal={reveal} onToggle={() => setReveal(r => !r)} count={sensitiveCount(req) + sensitiveCount(resp)} />
  return <div data-slot="exchange-tabs" className="min-w-0 border-t border-line pt-2.5">
    <div className="mb-1 flex min-w-0 gap-0.5" role="tablist" aria-label="Exchange detail">
      {XTABS.map(([k, l]) => <button key={k} type="button" role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
        className={cn('inline-flex h-[26px] flex-none cursor-pointer items-center rounded-control border-0 px-[9px] text-[12.5px] font-medium shadow-none transition-[background-color,color] duration-[var(--d1)]',
          tab === k ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg')}>{l}</button>)}
    </div>
    <div role="tabpanel" className="min-w-0">
      {tab === 'request' && <>
        <SubHead right={toggle}>Request headers</SubHead>
        {full ? <HeaderRows headers={req} flagged={new Set()} reveal={reveal} /> : <p className="text-fg-subtle!">Loading headers…</p>}
      </>}
      {tab === 'response' && <>
        <SubHead>Security headers</SubHead>
        <SecurityHeaderChips resp={resp} flagged={flagged} />
        <SubHead right={toggle}>Response headers</SubHead>
        {full ? <HeaderRows headers={resp} flagged={flagged} reveal={reveal} /> : <p className="text-fg-subtle!">Loading headers…</p>}
        <SubHead>{full ? 'Response body' : 'Body preview'}</SubHead>
        <BodyBlock body={reveal ? body : redactSecretText(body)} />
      </>}
      {tab === 'timing' && <TimingPanel x={x} base={model.base} />}
      {tab === 'raw' && <>
        <SubHead right={toggle}>Raw exchange</SubHead>
        <pre data-slot="exchange-raw" className={cn(RW.pre, 'max-h-[420px]')}>{rawText(full ?? x, reveal).slice(0, BODY_CAP)}</pre>
      </>}
    </div>
    <CompareWith self={full ?? x} candidates={candidates} />
  </div>
}

// ---------------------------------------------------------------- finding export (pure)

export interface FindingExportInput {
  id: string
  title?: string | null
  origin?: string | null
  cwe?: string | null
  category?: string | null
  reason?: string | null
  impact?: string | null
  remediation?: string | null
  recheck?: string | null
  verification?: string | null
  exchangeIds?: readonly string[] | null
}

/** Redacted Markdown for one finding (Export finding): labels are pre-rendered by the caller. */
export function formatFindingMarkdown(f: FindingExportInput, labels: { status: string; severity: string; fix?: string | null; link?: string | null }): string {
  const t = (v: unknown) => (typeof v === 'string' && v.trim() ? redactSecretText(v.trim()) : '')
  const section = (h: string, v: unknown) => (t(v) ? ['', `## ${h}`, '', t(v)] : [])
  return [
    `# ${t(f.title) || 'Untitled finding'}`, '',
    `- Status: ${labels.status}`, `- Severity: ${labels.severity}`,
    ...(labels.fix ? [`- Fix status: ${labels.fix}`] : []),
    ...(t(f.origin) ? [`- Origin: ${t(f.origin)}`] : []),
    ...([t(f.cwe), t(f.category)].filter(Boolean).length ? [`- Class: ${[t(f.cwe), t(f.category)].filter(Boolean).join(' · ')}`] : []),
    `- Finding ID: ${f.id}`,
    ...(labels.link ? [`- Link: ${labels.link}`] : []),
    ...section('What happened', f.reason), ...section('Why it matters', f.impact), ...section('Verification', f.verification),
    ...section('Remediation', f.remediation), ...section('Check the fix', f.recheck),
    ...(f.exchangeIds?.length ? ['', '## Evidence exchanges', '', ...f.exchangeIds.slice(0, 50).map(id => `- ${id}`)] : []),
    '', '_Exported from Kovo with sensitive headers and credential-shaped values redacted._', '',
  ].join('\n')
}
