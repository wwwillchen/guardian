/**
 * Typed floor candidate planner (`D2-TYPED-CANDIDATE-PLANNER`).
 *
 * Pure leaf helpers for Track D Cut 2 candidate enumeration:
 *  - maps differential probe anomalies / probe classes to `(specKind, vulnClass)` pairs,
 *  - builds zero-jq typed runner specs (`rce_proof`, `auth_protocol_proof`) with strict
 *    principal/control/variant binding, failing closed on unrecognized mutations or variants.
 */
import type { AuthMutation, ReplayStep } from '../replay-spec.ts'
import { baseFields } from './floor-heuristics.ts'
import type { EngineHypothesis, SynthesizedEngineSpec } from './floor-heuristics.ts'
import type { FloorRequestSpec } from './floor-recipes.ts'
import { injectUniversalParam } from './probes/context.ts'
import type { DifferentialResult } from './surface-engine.ts'

export interface FloorSpecKindPair {
  specKind: string
  vulnClass: string
}

export function requestFromInjection(input: {
  hyp: EngineHypothesis
  value: string
}): Pick<FloorRequestSpec, 'method' | 'pathAndQuery' | 'jsonBody' | 'textBody' | 'headers'> | null {
  const hyp = input.hyp
  const location = hyp.location ?? hyp.param?.location
  if (!hyp.param || !location) return null
  const injected = injectUniversalParam({
    pathAndQuery: hyp.pathAndQuery,
    param: hyp.param.name,
    paramLocation: location,
    value: input.value,
    method: hyp.method === 'DELETE' ? 'POST' : hyp.method,
    ...(hyp.headers ? { headers: hyp.headers } : {}),
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
    ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate.replaceAll('{{value}}', '{{val}}') } : {}),
    ...(hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery } : {}),
    ...(hyp.session ? { session: hyp.session } : {}),
  })
  let jsonBody: unknown
  let textBody: string | undefined
  if (typeof injected.body === 'string' && injected.body.length > 0) {
    const contentType = Object.entries(injected.headers ?? {})
      .find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? ''
    if (contentType.includes('json') || /^[{[]/.test(injected.body.trim())) {
      try { jsonBody = JSON.parse(injected.body) } catch { jsonBody = undefined }
    }
    if (jsonBody === undefined) textBody = injected.body
  }
  return {
    method: injected.method ?? hyp.method,
    pathAndQuery: injected.pathAndQuery,
    ...(jsonBody !== undefined ? { jsonBody } : {}),
    ...(textBody !== undefined ? { textBody } : {}),
    ...(injected.headers ? { headers: injected.headers } : {}),
  }
}

/** Anomaly-keyed capability evidence wins over the probe family (mirrors the retired synthesizer). */
export function anomalyCandidatePairs(probe: DifferentialResult): FloorSpecKindPair[] {
  if (probe.anomalies.some(anomaly => anomaly.type === 'secret_disclosed')) {
    return [{ specKind: 'http_chain', vulnClass: 'info_disclosure' }]
  }
  if (probe.anomalies.some(anomaly => anomaly.type === 'race_double_spend')) {
    return [{ specKind: 'race_burst', vulnClass: 'race_double_spend' }]
  }
  if (probe.anomalies.some(anomaly => anomaly.type === 'price_tampering')) {
    return [{ specKind: 'http_chain', vulnClass: 'price_tampering' }]
  }
  return []
}

export function probeClassCandidatePairs(hypothesis: EngineHypothesis, probe: DifferentialResult): FloorSpecKindPair[] {
  switch (hypothesis.probeClass) {
    case 'authz_matrix':
      return [{ specKind: 'http_chain', vulnClass: hypothesis.functionLevel ? 'bfla' : 'bola' }]
    case 'sqli_boolean':
      // A structural database-error signal replays through the typed injection_fingerprint recipe;
      // a paired predicate signal replays through boolean_or_timing. No anomaly of either shape
      // yields no candidate (the retired synthesizer also failed closed here).
      if (probe.anomalies.some(anomaly => anomaly.type === 'boolean_differential')) {
        return [{ specKind: 'sql_boolean_diff', vulnClass: 'sqli' }]
      }
      if (probe.anomalies.some(anomaly => anomaly.type === 'db_error_fingerprint')) {
        return [{ specKind: 'http_chain', vulnClass: 'injection' }]
      }
      return []
    case 'sqli_time_diff':
      return [{ specKind: 'sql_time_diff', vulnClass: 'sqli' }]
    case 'ssti_math':
      return [{ specKind: 'rce_proof', vulnClass: 'ssti' }]
    case 'command_injection':
      return [{ specKind: 'rce_proof', vulnClass: 'command_injection' }]
    case 'workflow_invariant':
      return [{ specKind: 'http_chain', vulnClass: 'workflow_bypass' }]
    case 'xxe_canary':
      return [{ specKind: 'http_chain', vulnClass: 'xxe' }]
    case 'ssrf_canary':
      return [{ specKind: 'http_chain', vulnClass: 'ssrf' }]
    case 'mass_assignment':
      return [{ specKind: 'http_chain', vulnClass: 'mass_assignment' }]
    case 'xss_context':
      return [{ specKind: 'browser_chain', vulnClass: 'xss_reflected' }]
    case 'csrf_state_change':
      return [{ specKind: 'http_chain', vulnClass: 'csrf' }]
    case 'auth_protocol_audit':
      return [{ specKind: 'auth_protocol_proof', vulnClass: 'jwt' }]
    case 'webhook_signature_bypass':
      return [{ specKind: 'http_chain', vulnClass: 'webhook_forgery' }]
    default:
      // path_traversal_benign, open_redirect_differential, graphql_audit, and every probe family
      // without a wired recipe or zero-jq runner fail closed with a named skip.
      return []
  }
}

const SSTI_PROOF_TEMPLATES: Readonly<Record<string, string>> = {
  'jinja2/twig': '{{{{nonce_a}}*{{nonce_b}}}}',
  erb: '<%={{nonce_a}}*{{nonce_b}}%>',
  'freemarker/el': '${{{nonce_a}}*{{nonce_b}}}',
  'spel/pebble': '#{{{nonce_a}}*{{nonce_b}}}',
  thymeleaf: '[[${{{nonce_a}}*{{nonce_b}}}]]',
}

const COMMAND_PROOF_CONNECTORS: Readonly<Record<string, (base: string) => string>> = {
  semicolon_echo: base => `${base}; echo {{nonce_part1}}$(echo ''){{nonce_part2}}`,
  subshell_echo: base => `${base}$(echo {{nonce_part1}}''{{nonce_part2}})`,
  quote_break: base => `${base}"; echo {{nonce_part1}}$(echo ''){{nonce_part2}}; "`,
  quote_break_id: base => `${base}"; echo {{nonce_part1}}$(echo ''){{nonce_part2}}; "`,
  pipe_echo: base => `${base} | echo {{nonce_part1}}$(echo ''){{nonce_part2}}`,
  backtick_echo: base => `${base}\`echo {{nonce_part1}}''{{nonce_part2}}\``,
}

/** Restore verifier-minted `{{nonce_*}}` placeholders that URL form/query encoding escaped. */
function restoreProofPlaceholders<T extends { pathAndQuery: string; textBody?: string }>(req: T): T {
  const restore = (value: string) => value.replace(/%7B%7B(nonce_[a-z0-9_]{1,26})%7D%7D/gi, '{{$1}}')
  return {
    ...req,
    pathAndQuery: restore(req.pathAndQuery),
    ...(req.textBody !== undefined ? { textBody: restore(req.textBody) } : {}),
  }
}

const SIMPLE_AUTH_MUTATION_KINDS: ReadonlySet<string> = new Set([
  'alg_none', 'strip_signature', 'expired_replay', 'rs256_to_hs256_jwks', 'jku_x5u_canary',
])
const SAFE_FIELD_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/

function floorReplayStep(input: {
  origin: string
  id: string
  role: 'control' | 'probe'
  description: string
  request: { method: string; pathAndQuery: string; jsonBody?: unknown; textBody?: string; headers?: Record<string, string> }
  persona?: string | null
  authMutation?: AuthMutation
  expectedStatus?: number[]
}): ReplayStep {
  return {
    id: input.id,
    role: input.role,
    description: input.description,
    ...(input.expectedStatus ? { expectedStatus: input.expectedStatus } : {}),
    request: {
      origin: input.origin,
      method: input.request.method as ReplayStep['request']['method'],
      pathAndQuery: input.request.pathAndQuery,
      followRedirects: false,
      ...(input.request.headers ? { headers: input.request.headers } : {}),
      ...(input.persona ? { persona: input.persona } : {}),
      ...(input.authMutation ? { authMutation: input.authMutation } : {}),
      ...(input.request.jsonBody !== undefined ? { jsonBody: input.request.jsonBody } : {}),
      ...(input.request.textBody !== undefined ? { textBody: input.request.textBody } : {}),
    },
  }
}

/** Build a zero-jq `rce_proof` from the arithmetic/echo evidence the probe already recorded. */
function buildRceCandidate(hypothesis: EngineHypothesis, probe: DifferentialResult): SynthesizedEngineSpec | null {
  const origin = hypothesis.endpoint.origin
  if (hypothesis.probeClass === 'ssti_math') {
    const hit = probe.anomalies.find(anomaly => anomaly.type === 'expression_evaluated')
    const template = hit ? SSTI_PROOF_TEMPLATES[String(hit.engine)] : undefined
    if (!hit || !template || !hypothesis.param) return null
    const control = requestFromInjection({ hyp: hypothesis, value: 'kovo' })
    const probeReq = requestFromInjection({ hyp: hypothesis, value: template })
    if (!control || !probeReq) return null
    const probeStepRequest = restoreProofPlaceholders(probeReq)
    return {
      kind: 'rce_proof',
      vulnClass: 'ssti',
      endpoint: hypothesis.endpoint.pathTemplate,
      spec: {
        ...baseFields(origin, 'Server-side template injection (arithmetic evaluation)', 'CWE-1336', 'injection-input', 'high'),
        kind: 'rce_proof',
        proofMode: 'dynamic_math',
        requiresTier3Approval: true,
        controlStep: floorReplayStep({ origin, id: 'c1', role: 'control', description: 'Benign template value', request: control, persona: hypothesis.ownerPersona }),
        probeStep: floorReplayStep({ origin, id: 'p1', role: 'probe', description: 'Verifier-minted arithmetic expression', request: probeStepRequest, persona: hypothesis.ownerPersona }),
      },
    }
  }
  if (hypothesis.probeClass === 'command_injection') {
    const hit = probe.anomalies.find(anomaly => anomaly.type === 'command_executed')
    if (!hit || !hypothesis.param) return null
    const base = String(hit.baseValue ?? '127.0.0.1').slice(0, 64)
    const variant = hit.variant == null ? 'semicolon_echo' : String(hit.variant)
    const connector = COMMAND_PROOF_CONNECTORS[variant]
    if (!connector) return null
    const control = requestFromInjection({ hyp: hypothesis, value: base })
    const probeReq = requestFromInjection({ hyp: hypothesis, value: connector(base) })
    if (!control || !probeReq) return null
    const probeStepRequest = restoreProofPlaceholders(probeReq)
    return {
      kind: 'rce_proof',
      vulnClass: 'command_injection',
      endpoint: hypothesis.endpoint.pathTemplate,
      spec: {
        ...baseFields(origin, 'Command injection via shell metacharacters (nonce echo proof)', 'CWE-78', 'injection-input', 'critical'),
        kind: 'rce_proof',
        proofMode: 'split_echo',
        requiresTier3Approval: true,
        controlStep: floorReplayStep({ origin, id: 'c1', role: 'control', description: 'Benign value', request: control, persona: hypothesis.ownerPersona }),
        probeStep: floorReplayStep({ origin, id: 'p1', role: 'probe', description: 'Verifier-minted split echo operands', request: probeStepRequest, persona: hypothesis.ownerPersona }),
      },
    }
  }
  return null
}

/** Build a zero-jq `auth_protocol_proof` for a recorded JWT verification-bypass anomaly. */
function buildAuthProtocolCandidate(hypothesis: EngineHypothesis, probe: DifferentialResult): SynthesizedEngineSpec | null {
  const hit = probe.anomalies.find(anomaly =>
    anomaly.type === 'jwt_auth_mutation_bypass' || anomaly.type === 'jwt_authorization_forgery' ||
    anomaly.type === 'jwt_body_token_bypass')
  if (!hit || !hypothesis.ownerPersona) return null
  const origin = hypothesis.endpoint.origin
  const path = hypothesis.pathAndQuery.split('?')[0] || hypothesis.pathAndQuery
  const title = 'JWT signature verification bypass'
  if (hit.type === 'jwt_authorization_forgery' || hit.type === 'jwt_body_token_bypass') {
    const rawPayload = hit.payload && typeof hit.payload === 'object' && !Array.isArray(hit.payload)
      ? hit.payload as Record<string, unknown>
      : (hypothesis.identityClaims ?? {})
    const payload: Record<string, string | number | boolean> = {}
    for (const [key, value] of Object.entries(rawPayload)) {
      if (!SAFE_FIELD_NAME_RE.test(key)) continue
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        payload[key] = typeof value === 'string' ? value.slice(0, 256) : value
      }
    }
    if (Object.keys(payload).length === 0) return null
    const declaredAlg = typeof hit.declaredAlg === 'string' && /^[A-Za-z0-9]{2,12}$/.test(hit.declaredAlg) ? hit.declaredAlg : 'HS256'
    const transport = hit.transport === 'body' ? 'body' : 'header'
    const field = typeof hit.tokenField === 'string' && SAFE_FIELD_NAME_RE.test(hit.tokenField) ? hit.tokenField : 'token'
    const body = hit.body && typeof hit.body === 'object' && !Array.isArray(hit.body) ? hit.body as Record<string, unknown> : {}
    const tokenMints = [
      { name: 'jwt_control', header: { alg: declaredAlg, typ: 'JWT' }, payload, signature: 'none' as const },
      { name: 'jwt_unsigned', header: { alg: 'none', typ: 'JWT' }, payload, signature: 'none' as const },
    ]
    const requestFor = (token: string): { method: string; pathAndQuery: string; headers: Record<string, string>; jsonBody?: unknown } => transport === 'body'
      ? {
          method: hypothesis.method === 'GET' ? 'POST' : hypothesis.method,
          pathAndQuery: path,
          headers: { 'Content-Type': 'application/json' },
          jsonBody: { ...body, [field]: token },
        }
      : {
          method: hypothesis.method,
          pathAndQuery: path,
          headers: { Authorization: `Bearer ${token}` },
        }
    return {
      kind: 'auth_protocol_proof',
      vulnClass: 'jwt',
      endpoint: hypothesis.endpoint.pathTemplate,
      spec: {
        ...baseFields(origin, `${title} (unsigned token accepted)`, 'CWE-347', 'jwt', 'high'),
        kind: 'auth_protocol_proof',
        protocol: 'jwt',
        tokenMints,
        steps: [
          floorReplayStep({ origin, id: 'c1', role: 'control', description: `Same claims under ${declaredAlg} with an invalid signature are rejected`, request: requestFor('{{jwt_control}}'), expectedStatus: [400, 401, 403] }),
          floorReplayStep({ origin, id: 'p1', role: 'probe', description: 'Unsigned alg=none token with the same claims is accepted', request: requestFor('{{jwt_unsigned}}'), expectedStatus: [200, 201, 204] }),
        ],
      },
    }
  }
  const mutation = typeof hit.mutation === 'string' ? hit.mutation : ''
  if (!SIMPLE_AUTH_MUTATION_KINDS.has(mutation)) return null
  const controlMutation: AuthMutation = mutation === 'expired_replay'
    ? { kind: 'strip_signature' }
    : { kind: 'expired_replay', skewSeconds: 86_400 }
  return {
    kind: 'auth_protocol_proof',
    vulnClass: 'jwt',
    endpoint: hypothesis.endpoint.pathTemplate,
    spec: {
      ...baseFields(origin, title, 'CWE-347', 'jwt', 'high'),
      kind: 'auth_protocol_proof',
      protocol: 'jwt',
      steps: [
        floorReplayStep({
          origin, id: 'c1', role: 'control', description: `Same principal with invalidated signature (${controlMutation.kind}) is rejected`,
          request: { method: hypothesis.method, pathAndQuery: path },
          persona: hypothesis.ownerPersona,
          authMutation: controlMutation,
          expectedStatus: [400, 401, 403],
        }),
        floorReplayStep({
          origin, id: 'p1', role: 'probe', description: `Mutated token (${mutation}) is accepted`,
          request: { method: hypothesis.method, pathAndQuery: path },
          persona: hypothesis.ownerPersona,
          authMutation: { kind: mutation } as AuthMutation,
          expectedStatus: [200, 201, 204],
        }),
      ],
    },
  }
}

export function buildTypedRunnerCandidate(pair: FloorSpecKindPair, hypothesis: EngineHypothesis, probe: DifferentialResult): SynthesizedEngineSpec | null {
  if (pair.specKind === 'rce_proof') return buildRceCandidate(hypothesis, probe)
  if (pair.specKind === 'auth_protocol_proof') return buildAuthProtocolCandidate(hypothesis, probe)
  return null
}
