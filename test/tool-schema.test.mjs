// Wire-schema gate for the syslog_* tools.
//
// `ToolDefinition.parameters` is NOT the plugin-authoring DSL. `ctx.tools.register()`
// stores it verbatim and it travels to the model provider untouched; the author
// DSL (`{ id: { type: 'string', required: true } }`) is a *build-time* input that
// only @deepseek-ai/dsh-tools' `defineTool` compiles into JSON Schema. Registering
// the DSL directly produced exactly this outage:
//
//   Invalid schema for function 'syslog_alert_detail': schema must be a JSON
//   Schema of 'type: "object"', got 'type: null'.
//
// Every model request died with it, so this is a whole-session failure, not a
// broken tool. bundle-gate.mjs greps the artefact for the shape; this test goes
// one step further and validates the objects the provider would actually receive,
// by activating the real bundle through the real cordis runtime and capturing
// every definition handed to the `tools` service.
//
//   node test/tool-schema.test.mjs [apiPort]
import { Context } from '@deepseek-ai/cordis'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const API_PORT = Number(process.argv[2] ?? 18814)
const SYSLOG_PORT = API_PORT + 1

let bad = 0
const check = (name, hit, detail) => {
  if (!hit) bad++
  console.log(`${hit ? '  ok  ' : '  MISS'} ${name}${hit || detail === undefined ? '' : ` 鈥?${detail}`}`)
}

// The raw JSON Schema subset DSH's `assertSupportedJsonSchema` enforces on
// anything it compiles, plus the annotations that may ride along.
const SCHEMA_KEYWORDS = new Set([
  'type', 'oneOf', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
  'description', 'title', 'default', 'examples',
])
const SCHEMA_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'null', 'array', 'object'])

/**
 * Collect every way a node would be rejected by the provider or by DSH.
 * A violation list (not a boolean) is the point: the next person needs to know
 * *which* tool and *which* keyword, or the failure reads as "schema is bad".
 */
function violationsIn(schema, path, out = []) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    out.push(`${path} is not a schema object (got ${JSON.stringify(schema)})`)
    return out
  }
  if (typeof schema.type !== 'string' || !SCHEMA_TYPES.has(schema.type)) {
    out.push(`${path}.type is ${JSON.stringify(schema.type)}`)
  }
  for (const key of Object.keys(schema)) {
    if (!SCHEMA_KEYWORDS.has(key)) out.push(`${path}.${key} is not a supported keyword`)
  }
  if (schema.type === 'object') {
    const properties = schema.properties
    if (!properties || typeof properties !== 'object' || Array.isArray(properties)) {
      out.push(`${path}.properties must be an object of schemas`)
    } else {
      for (const [name, child] of Object.entries(properties)) violationsIn(child, `${path}.properties.${name}`, out)
    }
    if (Object.hasOwn(schema, 'required')) {
      const required = schema.required
      if (!Array.isArray(required) || required.some((entry) => typeof entry !== 'string')) {
        out.push(`${path}.required must be an array of strings`)
      } else {
        for (const name of required) {
          if (!properties || !Object.hasOwn(properties, name)) out.push(`${path}.required names "${name}" which is not in properties`)
        }
      }
    }
    if (Object.hasOwn(schema, 'additionalProperties') && typeof schema.additionalProperties !== 'boolean') {
      out.push(`${path}.additionalProperties must be a boolean`)
    }
  }
  if (schema.type === 'array') {
    if (!Object.hasOwn(schema, 'items')) out.push(`${path}.items is missing`)
    else violationsIn(schema.items, `${path}.items`, out)
  }
  return out
}

// ---- activate the real bundle with a recording `tools` service ---------------
const registered = []
const ctx = new Context()
// A bare Context drops `warn` by default, and the plugin reports the reason a
// registration failed through logger.warn 鈥?invisible is the same as unlogged.
ctx.logger.exporter({ colors: 0, levels: { default: 3 }, export: (m) => console.error('[LOG]', m.level, m.name, ...m.args) })
await ctx.plugin({
  name: 'fake-tools',
  apply: (c) => c.provide('tools', {
    register(definition) {
      registered.push(definition)
      return () => {}
    },
  }),
})
await ctx.plugin({ name: 'fake-llm', apply: (c) => c.provide('llm', { stream: () => (async function* () {})(), listProviders: () => [] }) })

const dataDir = mkdtempSync(join(tmpdir(), 'syslog-toolschema-'))
const mod = await import(new URL('../dist/index.mjs', import.meta.url).href)
const fiber = await ctx.plugin(mod, { dataDir, apiPort: API_PORT, syslogPorts: [SYSLOG_PORT] })
await new Promise((r) => setTimeout(r, 500))

check('the plugin fiber reaches ACTIVE', fiber?.state === 2, `state=${fiber?.state}`)
check('all four syslog_* tools were registered', registered.length === 4,
  `got ${registered.length}: ${registered.map((d) => d?.name).join(', ')}`)
const names = registered.map((d) => d?.name).sort()
check('the registered names are the four expected tools',
  names.join(',') === 'syslog_alert_detail,syslog_alerts,syslog_conclude,syslog_stats', names.join(', '))

// ---- the contract the provider enforces -------------------------------------
// The root cause of the outage: a parameters object with no `type` at all.
for (const def of registered) {
  const name = def?.name ?? '(unnamed)'
  const parameters = def?.parameters
  check(`${name}: parameters root is an object schema`, parameters?.type === 'object',
    `type=${JSON.stringify(parameters?.type)}`)
  check(`${name}: parameters properties is a map`, !!parameters?.properties && typeof parameters.properties === 'object',
    JSON.stringify(parameters)?.slice(0, 120))
  const violations = violationsIn(parameters, `${name}.parameters`)
  check(`${name}: parameters are legal wire JSON Schema`, violations.length === 0, violations.join('; '))
  // register() rejects a def without an object-rooted output schema, so this
  // doubles as proof that the registration itself could not have been dropped.
  check(`${name}: an object-rooted output schema is attached`, def?.output?.schema?.type === 'object',
    JSON.stringify(def?.output?.schema))
  check(`${name}: a description is attached`, typeof def?.description === 'string' && def.description.length > 0)
}

// ---- the DSL must not come back ---------------------------------------------
// `required: true` is the author DSL's fingerprint and nothing else in this
// plugin emits it; `minimum`/`maximum` are numeric constraints outside the
// supported subset. Both were in the shipped definition that broke DSH.
const wire = JSON.stringify(registered)
check('no author-DSL requiredness survives into the wire schema', !/"required":true/.test(wire),
  (wire.match(/"required":true/g) ?? []).length + ' occurrence(s)')
check('no numeric range keyword survives into the wire schema', !/"(minimum|maximum)"/.test(wire),
  (wire.match(/"(minimum|maximum)"/g) ?? []).join(', '))

// The one tool that takes an id must still say so, or the model has no way to
// learn the argument is mandatory once the DSL sugar is gone.
for (const name of ['syslog_alert_detail']) {
  const def = registered.find((d) => d?.name === name)
  check(`${name}: id is declared required`, Array.isArray(def?.parameters?.required) && def.parameters.required.includes('id'),
    JSON.stringify(def?.parameters?.required))
}

await fiber?.dispose?.()
await new Promise((r) => setTimeout(r, 300))
rmSync(dataDir, { recursive: true, force: true })
console.log(`\n${bad === 0 ? 'TOOL SCHEMA OK' : `TOOL SCHEMA MISSING ${bad}`}`)
process.exit(bad === 0 ? 0 : 1)
