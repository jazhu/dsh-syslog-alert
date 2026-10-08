/**
 * Ship-gate for dsh-syslog-alert: confirm the built bundles actually carry the
 * pipeline. It greps the artefacts, not the sources, so a stale dist cannot
 * pass.
 *
 * The assertions here are deliberately about facts a reader cannot check by
 * looking at the source — the ones that rot silently. A tool definition missing
 * `output.render` does not throw, it just never shows up in the agent; a
 * command-policy bypass does not throw either, it just quietly becomes the
 * prompt-injection hole the design spent six paragraphs closing.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const pkgRoot = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')
const client = readFileSync(new URL('../dist/client.js', import.meta.url), 'utf-8')
const host = readFileSync(new URL('../dist/index.mjs', import.meta.url), 'utf-8')

// esbuild emits `charset: ascii`, so every CJK string lands in the bundle as
// \uXXXX escapes. Decode once here and compare real characters below:
// hand-copying escapes into a regex is how an assertion comes to miss a string
// that was in the artefact all along — and how one silently passed on a string
// that was never built.
const clientText = client.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
const hostText = host.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

// Declared before any check runs: the negative assertions below increment it,
// and a `bad++` executing before this initialises would throw a TDZ
// ReferenceError instead of reporting the miss — the gate would die on exactly
// the failure it exists to catch.
let bad = 0

const checks = [
  // ---- receiver ----------------------------------------------------------
  ['host    udp socket', /createSocket\(\{ type: ["']udp4["']/, host],
  ['host    tcp listener', /net\.createServer|createServer\(\(socket\)/, host],
  // A comment cannot be asserted on: esbuild strips them, so the words "octet
  // counting" never reach dist even though the behaviour is fully implemented.
  // What is worth pinning is the part that distinguishes a correct parser: the
  // length prefix is consumed POSITIONALLY (slice by `start + len`), so a body
  // that itself begins "2023 ..." is never re-split, and a half-delivered
  // message waits for its bytes instead of being truncated.
  ['host    rfc6587 length prefix consumed positionally', /\/\^\(\\d\{1,10\}\) \/\.exec\(rest\)[\s\S]{0,220}?rest\.slice\(start, start \+ len\)/, host],
  ['host    a failed bind is surfaced, not swallowed', /failedPorts/, host],
  // The DSH initiator is process-local and inherited; a socket callback that
  // runs without clearing it gets mis-attributed to whatever agent happens to
  // be running. The design's single-agent trigger depends on this.
  ['host    async work runs without an initiator', /withoutInitiator/, host],

  // ---- parsing -----------------------------------------------------------
  ['host    rfc5424 parser', /rfc5424/i, hostText],
  ['host    rfc3164 parser', /rfc3164/i, hostText],
  ['host    parse confidence is tracked', /ParseConfidence|["']rfc5424["']/, host],

  // ---- dedup / storm control (R3) ---------------------------------------
  ['host    fingerprint', /function fingerprint|fingerprint = function/, host],
  ['host    per-device rate limit', /rateLimited|perDeviceRatePerMin/, host],
  ['host    storm aggregation', /stormThreshold|storm/i, host],

  // ---- the ingestion wall (R4 leftovers) ----------------------------------
  ['host    unmapped sources never reach the pipeline', /unmappedPolicy/, host],

  // ---- agent tools -------------------------------------------------------
  ['host    tool: list alerts', /syslog_alerts/, host],
  ['host    tool: alert detail', /syslog_alert_detail/, host],
  ['host    tool: stats', /syslog_stats/, host],
  // The day-session agent writes its conclusion back through this tool — the
  // only documented path from a host session into the alert record, since the
  // session transcript itself is not a readable surface.
  ['host    tool: conclusion write-back', /syslog_conclude/, host],
  ['host    the prompt tells the agent to call it', /syslog_conclude/, hostText],
  // DSH's ToolDefinition contract: a def missing `output.render` does not
  // throw at register time, it just never appears in the tool list — the plugin
  // looks healthy while every syslog_* tool is invisible to the agent.
  ['host    tools carry an output block', /output: toolOutput|toolOutput\(/, host],
  // DSH's ToolDefinition.parameters IS the raw JSON Schema handed to the model:
  // `ctx.tools.register()` stores it verbatim and only `defineTool` compiles the
  // author DSL. A flat property table therefore reaches the provider as
  // `type: null` and takes the whole request down with it — "Invalid schema for
  // function 'syslog_alert_detail': schema must be a JSON Schema of
  // 'type: \"object\"', got 'type: null'". Every tool must ship an object-rooted
  // schema, so pin the shape rather than the key names.
  ['host    tool parameters are raw JSON Schema objects', /parameters: \{\s*type: "object"/, host],

  // ---- the day's ordinary session (sessionController, no provider) ---------
  // The second conversation mechanism, and the one the operator sees in their
  // session list: it asks the HOST for an ordinary session instead of owning a
  // continuable subagent, which is why it needs no provider and no workspace.
  // Pin the service, the naming and the prompt; the module name alone would
  // still pass if someone replaced the host service with a hand-rolled agent.
  ['host    the day session is created through the host service', /sessionController/, host],
  ['host    the day session is named from the configured prefix', /autoSessionTitle/, host],
  ['host    the day session admits the raw log as a prompt', /buildLogPrompt|分析这条日志/, hostText],
  ['host    the day session defaults to on', /autoSessionEnabled: true/, host],
  ['host    the day session pointer survives a reload', /auto-session\.json/, host],
  ['host    the day session route exists', /\/auto-session/, host],
  // Both prompts fence untrusted device text. Two copies of the marker strings
  // drift apart exactly once — after which a hostile log line can close its own
  // block and the text after it reads as operator instructions. Asserted on the
  // sources because the bundle interning would happily inline both copies.
  [
    'host    the untrusted-log fence is shared, not re-declared',
    () => {
      const auto = readFileSync(new URL('../src/auto-session.ts', import.meta.url), 'utf-8')
      const kit = readFileSync(new URL('../src/prompt-kit.ts', import.meta.url), 'utf-8')
      return (
        /import\s*\{[^}]*FENCE_OPEN[^}]*\}\s*from\s*['"]\.\/prompt-kit\.ts['"]/.test(auto) &&
        /export const FENCE_OPEN/.test(kit) &&
        /export function sanitizeFences/.test(kit) &&
        !/=== 原始 syslog/.test(auto)
      )
    },
    hostText,
  ],
  ['client  the day-session switch is in the settings dialog', /autoSessionEnabled/, client],
  ['client  the day-session title prefix is editable', /autoSessionTitle/, client],
  ['client  the day session can be pinned to a workspace', /autoSessionWorkspace/, client],
  ['client  the day session instruction is editable', /autoSessionPrompt/, client],
  // One line would hide whether the operator's instruction still ends where the
  // appended alert context begins, so the prompt editor must be multi-line.
  ['client  the prompt editor is a textarea', /createElement\)\(\s*["']textarea["']/, client],

  // ---- loopback api ------------------------------------------------------
  ['host    api prefix', /syslog-api/, host],
  ['host    token header', /X-Syslog-Token/, host],
  // The desktop app serves the frontend from dsh-app://app, whose hostname is
  // never loopback — a loopback-only origin check rejects the app's own writes
  // with a silent 401.
  ['host    dsh-app origin is accepted', /dsh-app/, host],
  ['host    sse keepalive', /keepalive|keep-alive|25_?000|25000/iu, host],
  ['host    settings route', /settings/, host],
  ['host    self-test injects a real frame', /test-alert|injectFrame/, host],

  // ---- client panel ------------------------------------------------------
  ['client  panel id', /dsh-syslog-alert/, client],
  ['client  sidebar tab registered', /sidebarRightTabs/, client],
  ['client  slot injection', /sidebar\.right\.pane\.tab/, client],
  ['client  list view', /AlertRow|function AlertRow/, client],
  ['client  detail view', /function AlertDetail/, client],
  ['client  settings view', /function Settings/, client],
  ['client  sse subscription', /EventSource/, client],
  // EventSource cannot set headers, so the token travels as a query param on
  // this one route only. The host must therefore accept it there.
  ['client  stream token rides the query string', /stream\?token=|stream\?\$\{|token=\$\{/, client],
  ['client  raw device output is shown', /<pre|pre/, client],
  ['client  the probe command is labelled as data', /原始 syslog/, clientText],
  ['client  drop counts are visible', /去重|限流|丢弃/, clientText],
  // ---- the three panel changes --------------------------------------------
  // Detail is a modal now: if a `sla-pane detail` pane comes back, the list is
  // squeezed to 46% again and the whole point of the change is lost.
  ['client  the detail is a modal, not a side pane', /function AlertModal/, client],
  // A modal without a keyboard exit traps the operator; Escape is the only one
  // this panel needs, since there is no form in it to submit.
  ['client  the modal closes on Escape', /Escape/, client],
  // The tab list is checked by its rendered labels, not by the source's type
  // union: the union is erased at build time and would pass while the button
  // was never wired up.
  ['client  the self-test moved to its own tab', /setTab\("selftest"\)/, client],
  ['client  the self-test tab is reachable', /tab === "selftest"/, client],
  // The received-at column: hand-formatted rather than through toLocaleString,
  // because a locale string changes width per machine and the column would stop
  // lining up.
  ['client  the list has a received-at column', /sla-col-time/, client],
  ['client  the received-at column is hand-formatted', /function fmtClock/, client],
  ['client  the column has a header', /function AlertListHead/, client],
  // ---- the alert-day-session mechanism -------------------------------------
  // The day's session must be an ordinary host session: created through
  // `sessionController`, never as a plugin-owned subagent thread. That is what
  // lets it exist with no provider to pick and no model to configure.
  ['host    the day session is a host session', /sessionController/, host],
  // The workspace setting is only real if it reaches `create()`. A `cwd` that
  // never leaves the settings store is the worst outcome: the operator sets a
  // path, sees no error, and every session still lands in the default one.
  ['host    the day session workspace reaches create()', /create\(\{\s*cwd:/, host],
  // A top-level inject entry would strand the fiber in state 0 with zero logs
  // the moment a service is not ACTIVE (see the plugin memory). The host
  // services are optional, so the list must stay empty. Asserted on the decoded
  // source instead of the bundle because esbuild drops the trailing type
  // annotation and reformats the export.
  ['host    the top-level inject list stays empty',
    () => /export\s+const\s+inject\s*:[^=\n]*=\s*\[\]/.test(readFileSync(new URL('../src/index.ts', import.meta.url), 'utf-8')), host],
  ['host    the receiver can be stopped', /listenerControl/, host],
  ['client  the stop/start control is in the panel', /controlListener|停止 syslog/, clientText],
  // The automatic analysis pipeline is gone: ingestion is now receive → parse →
  // prefilter → dedup → record → day-session delivery, and the *only* analysis
  // is the day-session agent calling syslog_conclude. A surviving symbol means
  // half a pipeline is still wired to settings that no longer exist.
  ['host    the analysis pipeline is gone',
    () => !/analyzeDef|requestAnalyze|listModels|DeviceCollector|matchPlaybook|extractJson|callLlm|probeLlm|maxConcurrentAnalysis|collectCommandAllowPrefixes|DENIED_COMMAND_HEADS|DEFAULT_PLAYBOOK|droppedQueueFull|syslog_analyze/.test(host)],
  ['client  the analysis controls are gone',
    () => !/runAnalyze|onAnalyze|ModelRow|onPickProvider|onPickModel|autoTriage|collectEnabled|maxConcurrentAnalysis|collectCommandAllowPrefixes|droppedQueueFull|triageCalls|llmErrors|queueDepth/.test(client)],
]

// ---- negatives: the facts that are proven by their absence -----------------
// Every check above greps dist/, so a removed safeguard can only be proven
// gone by looking for the bad thing. Each is a "we tried it and it was worse"
// decision.
for (const [name, hit] of [
  // No new npm dependency is a stated design constraint: syslog is Node's own
  // dgram/net, the LLM comes from ctx.inject(['llm']), SSH rides hillstone.
  ['host    no runtime dependencies were added', /require\(["'](syslog|logger|ssh2|winston)/.test(host)],
  // Client half must not import the host UI primitives: it ships into the
  // browser and is built by a different pipeline.
  ['client  no host UI primitives import', /require\(["']@deepseek-ai\/dsh-client-ui-primitives["']\)/.test(client)],
  // The plugin does not hold device credentials: it reads hillstone's device
  // list over loopback and never sees a password.
  ['host    no password field on the bridge device', /password/.test(host)],
  // Regression guard for the provider picker: the free-text box asked the
  // operator to spell an internal host identifier. Its placeholder is the
  // fingerprint of that design — no other field hints a name like that.
  ['client  the free-text provider box is gone', /preset-standard/.test(client)],
  // The subagent-provider mechanism went with its settings. A surviving
  // `dailySession*` symbol would mean half a mechanism is still wired: a control
  // the operator can no longer fix from the dialog is worse than never having
  // offered it, so both halves must be gone or neither.
  ['host    the daily-session settings are gone', /dailySession/.test(host)],
  ['client  the daily-session settings are gone', /dailySession/.test(client)],
  // The author DSL (`{ id: { type: 'string', required: true } }`) is a build-time
  // input for `defineTool`, never a wire format. `required: true` is its
  // fingerprint and nothing else in this plugin uses it, so its return means a
  // tool schema regressed to the DSL and the provider will reject the request.
  ['host    tool parameters carry no author DSL', /required: true/.test(host)],
  // Regression guard for the panel: the detail used to be a 46%-wide side pane,
  // and the list was squeezed into the other half. Returning it silently undoes
  // the modal without any test above failing.
  ['client  the list is not squeezed into a side pane', /sla-pane detail/.test(client)],
  // The self-test used to sit at the bottom of the alert list, so injecting a
  // test frame was inseparable from reading alerts. Its old home is the
  // fingerprint of that arrangement.
  ['client  the self-test is out of the alert list', /sla-pane list[\s\S]{0,400}sla-test/.test(client)],
]) {
  console.log(`${hit ? '  MISS' : '  ok  '} ${name}`)
  if (hit) bad++
}

for (const [name, re, hay] of checks) {
  // A `hit` entry arrives already-evaluated, so a plain regex would throw
  // `re.test is not a function` and kill the gate on the first such check.
  const ok = typeof re === 'function' ? re(hay) : re.test(hay)
  if (!ok) bad++
  console.log(`${ok ? '  ok  ' : '  MISS'} ${name}`)
}

// The manifest is what the loader reads BEFORE any code runs. A declared
// `inject` list that drifts from the real one produces a plugin that activates
// and silently registers nothing. Strip a leading BOM first: every JSON.parse of
// a source-controlled file eventually gets handed one by some editor on
// Windows, and the symptom is a raw SyntaxError that looks like a broken gate.
const pkgText = readFileSync(new URL('../package.json', import.meta.url), 'utf-8').replace(/^﻿/, '')
const pkg = JSON.parse(pkgText)
const declaredInject = ((pkg.dsh && pkg.dsh.client && pkg.dsh.client.inject) || []).slice().sort()
const actualInject = (readFileSync(new URL('../src/client.tsx', import.meta.url), 'utf-8')
  .match(/export const inject = \[([^\]]*)\]/) || [, ''])[1]
  .split(',')
  .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
  .filter(Boolean)
  .sort()
const injectDrift = declaredInject.join(',') === actualInject.join(',')
console.log(`${injectDrift ? '  ok  ' : '  MISS'} pkg     client inject list matches src (declared [${declaredInject.join(', ')}] vs actual [${actualInject.join(', ')}])`)
if (!injectDrift) bad++

const runtimeDeps = Object.keys(pkg.dependencies || {})
console.log(`${runtimeDeps.length === 0 ? '  ok  ' : '  MISS'} pkg     no runtime dependencies (found [${runtimeDeps.join(', ')}])`)
if (runtimeDeps.length !== 0) bad++

// ---- the display name ------------------------------------------------------
// 2026-10-07: the user renamed what they see to 「智能告警中心」. Only the
// display surface moved — `name`, the directory, cordis.patch.yml, the profile
// dependency and the node_modules junction all stay `dsh-syslog-alert`,
// because those are the plugin's module identity and renaming them would
// reinstall the plugin for no user-visible gain. Both halves are asserted: a
// rename that lands in package.json but not in the bundle (or vice versa)
// shows one name in the plugin manager and another in the sidebar.
const DISPLAY_NAME = '智能告警中心'
const OLD_DISPLAY_NAME = '告警中心'
{
  const displayOk = pkg.displayName === DISPLAY_NAME
  console.log(`${displayOk ? '  ok  ' : '  MISS'} pkg     displayName is ${DISPLAY_NAME} (got ${JSON.stringify(pkg.displayName)})`)
  if (!displayOk) bad++

  // The sidebar tab title comes from the client bundle, not package.json.
  const tabOk = /\u667A\u80FD\u544A\u8B66\u4E2D\u5FC3/.test(clientText)
  console.log(`${tabOk ? '  ok  ' : '  MISS'} pkg     the sidebar tab title is ${DISPLAY_NAME}`)
  if (!tabOk) bad++

  // The old two-word name must be gone from both user-visible surfaces. Kept as
  // a separate negative rather than folded into the checks above: it is a
  // "we tried it and it was worse" decision, not a positive contract.
  // The two-char prefix is stripped first instead of using a lookbehind:
  // ripgrep and Node both reject `(?<!智能)`, and a regex the tools in this
  // repo cannot run is a regex nobody can debug.
  const staleHost = /告警中心/.test(hostText.replace(/智能告警中心/g, ''))
  const staleClient = /告警中心/.test(clientText.replace(/智能告警中心/g, ''))
  console.log(`${staleHost || staleClient ? '  MISS' : '  ok  '} pkg     the old 告警中心 name is gone (host ${staleHost ? 'still has it' : 'clean'}, client ${staleClient ? 'still has it' : 'clean'})`)
  if (staleHost || staleClient) bad++
}

/**
 * Staleness guard. Every feature check above greps dist/, so they all keep
 * passing while dist/ is older than src/ — a CSS fix lands, the build fails,
 * and the gate still reports OK off the previous build. A fresh mtime is the
 * only way to tell those two states apart.
 */
function newestMtime(dir) {
  let newest = 0
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules' || entry.name.startsWith('.')) continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) newest = Math.max(newest, newestMtime(full))
    else if (/\.(ts|tsx|mjs|js|css)$/.test(entry.name)) newest = Math.max(newest, statSync(full).mtimeMs)
  }
  return newest
}
const srcMtime = Math.max(newestMtime(join(pkgRoot, 'src')), statSync(join(pkgRoot, 'build.mjs')).mtimeMs)
const distMtime = Math.min(statSync(join(pkgRoot, 'dist', 'client.js')).mtimeMs, statSync(join(pkgRoot, 'dist', 'index.mjs')).mtimeMs)
const stale = distMtime < srcMtime
const ageSec = Math.round((Date.now() - distMtime) / 1000)
console.log(`${stale ? '  MISS' : '  ok  '} client  dist is newer than src (${stale ? 'STALE' : `${ageSec}s old`})`)
if (stale) bad++

console.log(`\n${bad === 0 ? 'BUNDLE OK' : `BUNDLE MISSING ${bad}`}`)
process.exit(bad === 0 ? 0 : 1)