/**
 * Single-source field, route, role, shared engine types, and authorization heuristics for the
 * deterministic floor.
 *
 * Shared by `deterministic-engine.ts` and `floor-recipe-engine.ts` so live recipe planning and
 * hypothesis enumeration never silently drift.
 *
 * All regular expressions here are static literals (zero dynamic `RegExp` construction).
 */
import { randomBytes } from 'node:crypto'
import type { RoleName } from './oracle-invariants.ts'
import type { DifferentialProbeClass, SurfaceParamLocation } from './surface-engine.ts'

// ---------------------------------------------------------------------------------------------
// Shared deterministic-floor engine types & copy templates (consolidated from deleted deterministic-specs.ts)
// ---------------------------------------------------------------------------------------------

export interface EngineParam {
  name: string
  location: SurfaceParamLocation
  isObjectId?: boolean
  isCsrf?: boolean
  /** Schema-declared type from an OpenAPI/route map (string, integer, number, boolean, array, object). */
  declaredType?: string
  /** Runtime value shape observed in the target's own responses (url, path, xml, jwt, uuid, ...). */
  observedShape?: string
}

export interface EngineEndpoint {
  id: string
  origin: string
  method: string
  pathTemplate: string
  params: EngineParam[]
  riskScore?: number
  sinkKinds?: string[]
  source?: string
}

export type EngineIntent =
  | 'authz' | 'sqli' | 'ssti' | 'command_injection' | 'xxe' | 'ssrf' | 'traversal' | 'redirect' | 'xss' | 'graphql'
  | 'mass_assignment' | 'cache' | 'stored_xss' | 'csrf' | 'workflow' | 'race' | 'webhook' | 'auth_protocol' | 'secret_disclosure'

export interface EngineHypothesis {
  key: string
  endpoint: EngineEndpoint
  probeClass: DifferentialProbeClass
  intent: EngineIntent
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** Probe/replay path. Object-level authz hypotheses keep a `{{id}}` placeholder. */
  pathAndQuery: string
  param?: EngineParam
  location?: SurfaceParamLocation
  ownerPersona?: string
  otherPersona?: string
  resourceIds?: string[]
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  baselineValue?: string
  candidateFields?: string[]
  candidateValues?: Record<string, string | boolean | number>
  ssrfParams?: string[]
  functionLevel?: boolean
  idParamName?: string
  triggerPath?: string
  readPath?: string
  workflowListPath?: string
  workflowReadPath?: string
  workflowTargetTemplate?: string
  repeatTransition?: boolean
  quantityField?: string
  headers?: Record<string, string>
  flowCreatePath?: string
  priceTrust?: boolean
  raceBurst?: boolean
  session?: string
  graphqlRoots?: string[]
  graphqlSeedsByRoot?: Record<string, string[]>
  stateField?: string
  bodyField?: string
  createReadTemplate?: string
  secretScan?: boolean
  viewerPersona?: string
  csrfBind?: boolean
  readbackPath?: string
  readbackPersona?: string
  functionState?: {
    bindings: Array<{ field: string; value: string }>
    reset?: Array<{ field: string; value: string }>
    body?: Record<string, unknown>
  }
  authzRequiredRole?: 'viewer' | 'member' | 'admin' | 'owner'
  reservedVictimId?: string
  tokenFields?: string[]
  identityClaims?: Record<string, string>
  webhookBody?: Record<string, unknown>
  webhookHeader?: string
  risk: number
  notes?: string[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface SynthesizedEngineSpec {
  kind: string
  /** Canonical class label used for attribution/dedupe (benchmark-compatible spelling). */
  vulnClass: string
  endpoint: string
  spec: Record<string, unknown>
  /** Runtime evidence collected for durable `pending_oob` correlation. */
  evidence?: Record<string, unknown>
}

interface FloorClassCopyTemplate {
  impact: string
  remediation: string
}

const FLOOR_COPY_BY_CLASS: Readonly<Record<string, FloorClassCopyTemplate>> = {
  bola: {
    impact: 'An authenticated actor can read or alter resources belonging to another user or tenant.',
    remediation: 'Enforce server-side object-level ownership and tenant authorization checks on every request naming a resource identifier.',
  },
  bfla: {
    impact: 'A lower-privileged actor can invoke a privileged administrative or role-gated function.',
    remediation: 'Enforce explicit server-side role and capability checks on every privileged endpoint rather than relying on client-side controls.',
  },
  sqli: {
    impact: 'Untrusted input alters server-side database query structure or evaluation.',
    remediation: 'Use parameterized queries or prepared statements and strict input validation; never concatenate untrusted input into queries.',
  },
  xxe: {
    impact: 'The XML parser resolves attacker-supplied external entities, enabling server-side file reads or out-of-band network callbacks.',
    remediation: 'Disable external entity resolution and DTD processing in the XML parser configuration.',
  },
  ssrf: {
    impact: 'The server issues outbound network requests to attacker-controlled destinations, exposing internal services or metadata endpoints.',
    remediation: 'Validate and allowlist outbound destination hosts and schemes; block private, loopback, and link-local IP ranges after DNS resolution.',
  },
  path_traversal: {
    impact: 'Attacker-supplied path input escapes the intended server root directory, allowing arbitrary file reads.',
    remediation: 'Canonicalize file paths server-side and verify the resolved path remains strictly inside the permitted base directory.',
  },
  open_redirect: {
    impact: 'Unvalidated redirect targets send users to attacker-controlled external origins.',
    remediation: 'Restrict redirect destinations to relative paths or an explicit allowlist of trusted origins.',
  },
  mass_assignment: {
    impact: 'Over-posted request fields persist privileged or protected attributes that the caller is not permitted to set.',
    remediation: 'Explicitly allowlist client-assignable fields and bind protected attributes server-side from trusted session context.',
  },
  csrf: {
    impact: 'A cross-site request can trigger state-changing actions using the victim’s ambient session credentials without an anti-CSRF token.',
    remediation: 'Require a validated per-session anti-CSRF token on state-changing routes and enforce SameSite cookie attributes.',
  },
  info_disclosure: {
    impact: 'Sensitive credentials, secrets, or audit records are exposed in responses returned to unentitled callers.',
    remediation: 'Remove credentials and internal secrets from response payloads and audit logs, and enforce server-side field filtering.',
  },
  xss: {
    impact: 'Untrusted input is rendered as executable script markup in a victim’s browser context.',
    remediation: 'Apply context-appropriate output encoding, sanitize rich HTML safely, and enforce a strict Content-Security-Policy.',
  },
  ssti: {
    impact: 'Untrusted input is evaluated as server-side template expressions, enabling server-side code execution.',
    remediation: 'Pass user input strictly as template data rather than template source, and use a sandboxed or logic-less template engine.',
  },
  cmdi: {
    impact: 'Untrusted input injects shell metacharacters into server-side operating system commands, enabling arbitrary command execution.',
    remediation: 'Execute commands with explicit argv arrays without invoking a shell, and strictly allowlist dynamic arguments.',
  },
  business_logic: {
    impact: 'Application workflow or state-machine invariants can be bypassed or replayed out of sequence.',
    remediation: 'Enforce state-transition and business-rule invariants atomically server-side before committing state changes.',
  },
  price_tampering: {
    impact: 'Client-supplied pricing or amount parameters override server-side authoritative totals during checkout or payment processing.',
    remediation: 'Compute prices, discounts, and totals strictly server-side from authoritative catalog records and ignore client-supplied amounts.',
  },
  race_double_spend: {
    impact: 'Concurrent requests race a non-atomic balance or quota check, allowing double-spend or duplicate state transitions.',
    remediation: 'Serialize balance and quota transitions using database transactions, row locks, unique constraints, or idempotency keys.',
  },
  jwt: {
    impact: 'Forged or unsigned authentication tokens bypass signature verification and grant authenticated session access.',
    remediation: 'Verify token signatures against an explicit algorithm allowlist and server-managed keys; reject unsigned (alg=none) and unverified tokens.',
  },
  webhook: {
    impact: 'Unsigned or forged webhook deliveries are accepted and processed without valid cryptographic signature verification.',
    remediation: 'Verify webhook HMAC signatures in constant time against the raw request body using a server-managed secret before processing events.',
  },
}

const DEFAULT_FLOOR_COPY: FloorClassCopyTemplate = {
  impact: 'A deterministic verification differential confirmed exploitable server-side behavior on the target endpoint.',
  remediation: 'Validate untrusted input and enforce strict server-side security controls on the affected endpoint.',
}

const FLOOR_COPY_BY_CWE: Readonly<Record<number, string>> = {
  639: 'bola', 284: 'bola', 566: 'bola',
  285: 'bfla', 269: 'bfla', 862: 'bfla', 863: 'bfla',
  89: 'sqli', 564: 'sqli', 943: 'sqli',
  611: 'xxe', 918: 'ssrf',
  22: 'path_traversal', 23: 'path_traversal', 73: 'path_traversal',
  601: 'open_redirect', 915: 'mass_assignment', 352: 'csrf',
  200: 'info_disclosure', 359: 'info_disclosure', 522: 'info_disclosure', 532: 'info_disclosure',
  79: 'xss', 80: 'xss', 83: 'xss',
  1336: 'ssti', 94: 'ssti', 78: 'cmdi', 77: 'cmdi',
  840: 'business_logic', 841: 'business_logic', 1284: 'business_logic',
  472: 'price_tampering', 362: 'race_double_spend', 367: 'race_double_spend',
  347: 'jwt', 287: 'jwt', 345: 'webhook',
}

function floorCopyTemplateFor(cwe: string, category: string): FloorClassCopyTemplate {
  const cweMatch = /^CWE-(\d+)$/i.exec(cwe.trim())
  if (cweMatch) {
    const key = FLOOR_COPY_BY_CWE[Number(cweMatch[1])]
    if (key && FLOOR_COPY_BY_CLASS[key]) return FLOOR_COPY_BY_CLASS[key]!
  }
  const normCat = category.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (normCat === 'broken_access_control' || normCat === 'idor' || normCat === 'cross_tenant_read' || normCat === 'cross_tenant_write') return FLOOR_COPY_BY_CLASS.bola!
  if (normCat === 'sensitive_data_exposure' || normCat === 'information_disclosure' || normCat === 'secret_disclosure') return FLOOR_COPY_BY_CLASS.info_disclosure!
  if (normCat === 'xss_reflected' || normCat === 'xss_stored' || normCat === 'dom_xss') return FLOOR_COPY_BY_CLASS.xss!
  if (normCat === 'workflow_bypass' || normCat === 'workflow_skip') return FLOOR_COPY_BY_CLASS.business_logic!
  if (normCat === 'webhook_forgery') return FLOOR_COPY_BY_CLASS.webhook!
  if (normCat === 'url_redirect') return FLOOR_COPY_BY_CLASS.open_redirect!
  return FLOOR_COPY_BY_CLASS[normCat] ?? DEFAULT_FLOOR_COPY
}

export function baseFields(
  origin: string,
  title: string,
  cwe: string,
  category: string,
  severity: Severity,
  jq?: string,
) {
  const copy = floorCopyTemplateFor(cwe, category)
  return {
    version: 1 as const,
    origin,
    title: title.slice(0, 200),
    category,
    cwe,
    severity,
    severityRationale: 'Deterministic differential evidence was reproduced by the Zero-LLM verifier.',
    impact: copy.impact,
    remediation: copy.remediation,
    recheckInstructions: 'Replay the control and probe requests and compare the responses.',
    ...(jq !== undefined ? { assertionsJq: jq } : {}),
  }
}

// ---------------------------------------------------------------------------------------------
// Route, action, and identity classification
// ---------------------------------------------------------------------------------------------

/** Routes whose name marks an elevated/privileged function (admin console, role grant, flags...). */
export const PRIVILEGED_ACTION_RE =
  /(?:^|[/_.-])(?:admin|administrator|administration|internal|manage|management|staff|superuser|privileged|backoffice|permissions?|roles?|grants?|scopes?|impersonate|feature[-_]?flags?)(?:$|[/_.-])/i

/** Read routes whose primary security property is credential/audit disclosure rather than body-equality BOLA. */
export const SENSITIVE_READ_ROUTE_RE =
  /(?:^|[/_.-])(?:tokens?|keys?|secrets?|audit|auditlog|activity|logs?|config|export|apikeys?|links?|integrations?)(?:$|[/_.-])/i

/**
 * Route shapes that hand the caller a new acting identity/scope (impersonation, act-as, tenant
 * switch). Mutating probes on these routes can change the instrument's own session, so their
 * bodies are restricted to benign content fields and mass-assignment is not run there.
 */
export const IDENTITY_ASSUMPTION_ROUTE_RE =
  /(?:^|[/_.-])(?:impersonat\w*|act[-_]?as|sudo|assume[-_]?role|switch[-_]?(?:tenant|org|store|user|account)|sts)(?:$|[/_.-])/i

/** Dynamic path-segment shapes shared by route normalization, readback inference, and replay. */
export const DYNAMIC_ID_SEGMENT_RE =
  /(?:\/:[A-Za-z_][A-Za-z0-9_]*|\/\{\{id\}\}|\/\{[A-Za-z0-9_]+\}|\/\[[^\]]+\])/
export const PLACEHOLDER_SEGMENT_RE = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/

export function hasDynamicIdSegment(path: string): boolean {
  return DYNAMIC_ID_SEGMENT_RE.test(path.split('?')[0])
}

export function pathHasFileHint(path: string): boolean {
  return /(?:^|[/_.-])(?:download|downloads|file|files|asset|assets|view|serve|log|logs|journal|journals|billing[-_]?docs?|document|documents|attachment|attachments|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasUrlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:avatar|avatars|image|images|photo|photos|logo|logos|media|thumbnail|webhook|webhooks|hook|hooks|callback|callbacks|integration|integrations|connector|connectors|proxy|proxies|fetch|remote|link|links|manifest|manifests)(?:$|[/_.-])/i.test(path)
}

export function pathHasXmlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:xml|import|imports|soap|saml|sso|svg|rss|wsdl|manifest|manifests|feed|feeds|upload|uploads|parse|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasTemplateHint(path: string): boolean {
  return /(?:^|[/_.-])(?:render|preview|template|templates|layout|layouts|report|reports|docs?|pages?|email|emails|snippet|snippets)(?:$|[/_.-])/i.test(path)
}

/**
 * Search-surface vocabulary. Membership is tested against whole path segments and whole tokens
 * within a segment (split on `-`, `_`, `.`), never as a substring of a longer word. `catalog` is a
 * listing noun, not a search surface and deliberately absent: derived `catalog*` routes must not
 * spend the SQL-injection quota without evidence that they read a query.
 */
const SEARCH_HINT_TOKENS: ReadonlySet<string> = new Set([
  'search', 'searches', 'lookup', 'find', 'filter', 'query', 'queries', 'browse',
])

function pathSegmentsOf(path: string): string[] {
  return (path.split('?')[0] || '/').split('/').filter(Boolean)
}

/** Match a resource noun or its simple plural against whole path segments, never a substring. */
export function pathHasNounSegment(path: string, noun: string, lastOnly = false): boolean {
  const segments = pathSegmentsOf(path)
  const candidates = lastOnly ? segments.slice(-1) : segments
  const lower = noun.toLowerCase()
  return candidates.some(segment => {
    const value = segment.toLowerCase()
    return value === lower || value === `${lower}s`
  })
}

function segmentTokens(segment: string): string[] {
  return segment.toLowerCase().split(/[-_.]+/).filter(Boolean)
}

export function pathHasSearchHint(path: string): boolean {
  return pathSegmentsOf(path).some(segment => segmentTokens(segment).some(token => SEARCH_HINT_TOKENS.has(token)))
}

/** A route whose shape says it runs an operator-supplied host/command probe. */
export function pathHasCommandHint(path: string): boolean {
  return /(?:^|[/_.-])(?:diag|diagnostics?|exec|execute|command|cmd|shell|ping|nslookup|lookup|resolve|whois|healthcheck|system)(?:$|[/_.-])/i.test(path)
}

export function pathHasPrivilegedHint(path: string): boolean {
  return PRIVILEGED_ACTION_RE.test(path)
}

export function pathHasRedirectHint(path: string): boolean {
  return /(?:^|[/_.-])(?:redirect|return|callback|continue|resume|sso|oauth|authorize|checkout|download|export|next)(?:$|[/_.-])/i.test(path)
}

/** Field names that select or change identity/scope rather than describing record content. */
export function isIdentityAssignmentField(field: string): boolean {
  const snake = field.replace(/[A-Z]/g, ch => '_' + ch.toLowerCase()).replace(/[-.]/g, '_')
  return /^(?:is_?_?admin|admin|role|roles|permission|permissions|privilege|privileges|grant|level|tenant|tenant_id|org|org_id|store|store_id|team|team_id|account|account_id|owner|owner_id|scope|acting|act_as|workspace|workspace_id|user|user_id|actor|subject|email)$/.test(snake)
}

/** Drop identity/scope selectors from a probe body (shallow and nested object levels). */
export function withoutIdentityFields(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [field, value] of Object.entries(body)) {
    if (isIdentityAssignmentField(field)) continue
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const nested = withoutIdentityFields(value as Record<string, unknown>)
      if (Object.keys(nested).length > 0) out[field] = nested
      continue
    }
    out[field] = value
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Baseline write & privilege-escalation field classification
// ---------------------------------------------------------------------------------------------

export const BASELINE_STRONG_NUMERIC_FIELD_RE =
  /(?:^|[_-])(?:amount|total|price|value|cents|balance|qty|quantity|count|seats?|credits?)(?:$|[_-])/i
export const BASELINE_TEXT_FIELD_RE =
  /^(?:name|title|label|description|note|notes|body|text|summary|message|subject|comment|company|address)$/i
export const BASELINE_WEAK_NUMERIC_FIELD_RE =
  /^(?:number|num|limit|score|rating|page|size|order)$/i
export const BASELINE_EXCLUDED_FIELD_RE =
  /(?:^|[_-])(?:id|uuid|owner|tenant|org|team|role|roles|permissions?|email|password|token|secret|key|status|state|created|updated)(?:$|[_-])/i
/** Scope/identity selectors: writing these changes which record is addressed, not its content. */
export const BASELINE_SELECTOR_FIELD_RE =
  /(?:^|[_-])(?:id|uuid|owner|tenant|org|team|role|roles|permissions?|email|password|token|secret|key|created|updated)(?:$|[_-])/i
export const BASELINE_STATE_FIELD_RE =
  /^(?:status|state|stage|phase|payment_state|fulfil?lment_state|lifecycle|visibility|priority|archived?|active)$/i
export const CONSERVED_BALANCE_FIELD_RE = /balance|available|remaining|stock|on_?hand|quantity|credits?|points?/i
export const CONSERVED_ECHO_FIELD_RE = /transfer|debit|charge|amount|count|redeem|used|quantity|qty|reserved/i
export const CONSERVED_AMOUNT_FIELD_RE = /^(?:item_?|line_?|requested_?|reserved_?|redeem_?)?(?:amount|value|quantity|qty|count|units|seats|credits|points|total|redeem)$/i

// ---------------------------------------------------------------------------------------------
// Safe identifier / field / persona guards
// ---------------------------------------------------------------------------------------------

export const SAFE_RESOURCE_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/
export const SAFE_FIELD_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/

export function isSafeResourceId(value: unknown): value is string {
  return typeof value === 'string' && SAFE_RESOURCE_ID_RE.test(value)
}

export function isSafeFieldName(value: unknown): value is string {
  return typeof value === 'string' && SAFE_FIELD_NAME_RE.test(value)
}

export function fillResourceId(pathAndQuery: string, id: string): string {
  return pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
}

/**
 * A syntactically valid identifier that must not resolve to any real object. Used as a negative
 * control so a route that ignores its identifier (and serves the caller's own session object)
 * cannot be mistaken for an object-level authorization failure.
 */
export function bogusIdFor(id: string): string {
  if (/^\d{1,12}$/.test(id)) {
    const n = Number(id)
    if (Number.isSafeInteger(n)) {
      const bumped = n + 9_000_001
      if (String(bumped).length <= 12) return String(bumped)
    }
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    const tail = id.slice(-1) === '0' ? '1' : '0'
    return `${id.slice(0, -1)}${tail}`
  }
  if (/^[A-Za-z]+[-_][A-Za-z0-9]+$/.test(id)) {
    const sep = id.includes('_') ? '_' : '-'
    return `${id.split(/[-_]/)[0]}${sep}gx9000001`
  }
  return `gx${randomBytes(8).toString('hex')}`
}

// ---------------------------------------------------------------------------------------------
// Posture / role privilege rankings
// ---------------------------------------------------------------------------------------------

export const ROLE_PRIVILEGE_RANK: Readonly<Record<string, number>> = {
  superadmin: 5,
  owner: 4,
  admin: 4,
  manager: 3,
  editor: 3,
  moderator: 3,
  member: 2,
  user: 2,
  viewer: 1,
  readonly: 1,
  guest: 0,
  anonymous: 0,
}

export function rolePrivilegeRank(role: RoleName | null | undefined): number | null {
  if (!role) return null
  return Object.prototype.hasOwnProperty.call(ROLE_PRIVILEGE_RANK, role) ? ROLE_PRIVILEGE_RANK[role]! : null
}

export const POSTURE_CWES: ReadonlySet<string> = new Set([
  'CWE-16', 'CWE-200', 'CWE-209', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-306', 'CWE-319', 'CWE-326',
  'CWE-346', 'CWE-523', 'CWE-538', 'CWE-540', 'CWE-614', 'CWE-639', 'CWE-693', 'CWE-862', 'CWE-863', 'CWE-942',
  'CWE-1004', 'CWE-1021',
])

export const POSTURE_CATEGORY_RE =
  /access|auth|bypass|cors|header|posture|misconfig|exposure|session|cookie|transport|tls|csp|policy|idor|bola|bfla/i

// ---------------------------------------------------------------------------------------------
// Shared authorization readback, baseline write, and matrix admissibility helpers
// ---------------------------------------------------------------------------------------------

export interface AuthzReadbackTemplate {
  /** Read route with its `{{id}}` placeholder still in place. */
  template: string
  /** Actor for the read when it is the mutated actor's own identity route. */
  persona?: string
}

/**
 * Resolve the readback route template for a mutating authorization proof:
 * explicit harvested readback route, the object's REST detail route (dropping a trailing
 * privileged action verb), or the function's own surface for an elevated action.
 */
export function resolveAuthzReadbackTemplate(
  input: { pathAndQuery: string; readbackPath?: string; readbackPersona?: string },
  functionLevel: boolean,
): AuthzReadbackTemplate | null {
  if (input.readbackPath) {
    return {
      template: input.readbackPath,
      ...(input.readbackPersona ? { persona: input.readbackPersona } : {}),
    }
  }
  const pathAndQuery = input.pathAndQuery
  const bare = pathAndQuery.split('?')[0]!
  if (functionLevel) return PRIVILEGED_ACTION_RE.test(bare) ? { template: pathAndQuery } : null
  const queryAt = pathAndQuery.indexOf('?')
  if (queryAt >= 0 && pathAndQuery.slice(queryAt).includes('{{id}}')) return { template: pathAndQuery }
  const segments = bare.split('/')
  const placeholder = segments.findIndex(seg =>
    seg === '{{id}}' || /^\{[^}]+\}$/.test(seg) || /^:[A-Za-z_][A-Za-z0-9_]*$/.test(seg))
  if (placeholder <= 0) return null
  if (placeholder === segments.length - 1) return { template: pathAndQuery }
  if (placeholder === segments.length - 2 && PRIVILEGED_ACTION_RE.test(bare)) {
    return { template: segments.slice(0, -1).join('/') }
  }
  return null
}

export interface BaselineWrite {
  field: string
  baselineValue: string | number | boolean
  probeValue: string | number | boolean
  baselineBody: Record<string, unknown>
}

/**
 * Choose a fresh baseline value for one mutable scalar field of a probe body so the probe write
 * creates a genuine non-idempotent delta against the pre-mutation readback.
 */
export function pickBaselineWrite(bodyTemplate: unknown): BaselineWrite | null {
  if (!bodyTemplate || typeof bodyTemplate !== 'object' || Array.isArray(bodyTemplate)) return null
  const record = bodyTemplate as Record<string, unknown>
  const scalarEntries = Object.entries(record).filter(([field, value]) =>
    SAFE_FIELD_NAME_RE.test(field) &&
    (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'))
  const entries = scalarEntries.filter(([field]) => !BASELINE_EXCLUDED_FIELD_RE.test(field))
  const chosen = entries.find(([field]) => BASELINE_STRONG_NUMERIC_FIELD_RE.test(field))
    ?? entries.find(([field]) => BASELINE_TEXT_FIELD_RE.test(field))
    ?? entries.find(([, value]) => typeof value === 'boolean')
    ?? entries.find(([field]) => BASELINE_WEAK_NUMERIC_FIELD_RE.test(field))
    ?? scalarEntries.find(([field]) => BASELINE_STATE_FIELD_RE.test(field))
    ?? scalarEntries.find(([field]) => !BASELINE_SELECTOR_FIELD_RE.test(field))
  if (!chosen) return null
  const [field, value] = chosen
  const nonce = randomBytes(4).toString('hex')
  if (typeof value === 'boolean') {
    const baselineValue = !value
    return { field, baselineValue, probeValue: value, baselineBody: { ...record, [field]: baselineValue } }
  }
  if (typeof value === 'number' || /^-?\d+(?:\.\d+)?$/.test(String(value))) {
    const base = 424_242 + (Number.parseInt(nonce.slice(0, 4), 16) % 1_000)
    return { field, baselineValue: base, probeValue: base + 1, baselineBody: { ...record, [field]: base } }
  }
  const baselineValue = `kovo-baseline-${nonce}`
  return { field, baselineValue, probeValue: `kovo-probe-${nonce}`, baselineBody: { ...record, [field]: baselineValue } }
}

