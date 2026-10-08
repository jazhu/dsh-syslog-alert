// dsh-syslog-alert — plugin assembly.
//
// The pipeline, in the order frames travel through it:
//
//   socket → parse → prefilter → fingerprint dedup → per-device rate limit →
//   alert record → day-session delivery → SSE
//
// Everything here is synchronous and cheap: there is no analysis queue and no
// model call in this plugin. The deep read of each alert happens in the day's
// ordinary DSH session (see auto-session), and the agent there writes its
// conclusion back through the `syslog_conclude` tool.
//
// The frame handler runs outside any DSH agent context. `withoutInitiator` is
// what keeps a 3am syslog delivery from being attributed to whatever
// conversation happened to be running when the datagram landed.

import { createServer } from 'node:http'
import { appendFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Alert, Config, EditableSettings, SyslogMessage } from './types.ts'
import { AlertStore, StatsCounter } from './alert-store.ts'
import { fingerprint, mapSourceToDevice, prefilter, type DeviceLike } from './fingerprint.ts'
import { parseSyslogFrame, splitFrames } from './syslog-parse.ts'
import { SyslogReceiver, type ReceivedFrame } from './syslog-server.ts'
import { API_PREFIX, SseHub, handleApi, originIsLocalOrAbsent } from './syslog-api.ts'
import { AutoSessionRunner, type AutoSessionStatus, type SessionControllerLike } from './auto-session.ts'
import { DEFAULT_CONFIG, SettingsStore, resolveConfig } from './settings.ts'

export const name = 'dsh-syslog-alert'

// No top-level service injection on purpose.
//
// cordis keeps a fiber INACTIVE (`state: 0`, silently — no log line) until every
// name in a top-level `inject` list has an ACTIVE provider
// (`_refresh()` sets `epoch = INACTIVE` on the first missing one). Declaring
// `agents`/`tools` up front therefore means the receiver, the store and the
// whole API stay dead until the last of those appears — and if the host ever
// lacks one, this plugin never runs at all, which looks exactly like a firewall
// problem.
//
// None of them is strictly required: the syslog receiver, the alert store and
// the loopback API work with no tools present, and the day session needs the
// host's `sessionController` only. So we declare nothing and take each service
// reactively via `ctx.inject([...])` inside activate() — the same shape
// dsh-hillstone-cli-ops uses.
export const inject: readonly string[] = []

interface ContextLike {
  effect(body: () => (() => void) | void, label?: string): void
  inject(deps: readonly string[], callback: (ctx: any) => void): () => void
  logger?: { warn(message: string): void; info?(message: string): void }
  getConfigPath?: () => string | undefined
  baseDir?: string
}

const TAG = '[dsh-syslog-alert]'

function readProfileDir(ctx: ContextLike): string | undefined {
  for (const key of ['baseDir', 'getConfigPath']) {
    try {
      const value = (ctx as any)[key]
      const v = typeof value === 'function' ? value.call(ctx) : value
      if (typeof v === 'string' && v) return v
    } catch {
      /* cordis proxy throws on undeclared keys; that is not an error here */
    }
  }
  return undefined
}

/**
 * Best-effort handle on the host `sessionController` service.
 *
 * The service belongs to a sibling fiber, so a bare `ctx.sessionController`
 * read is illegal here, and `ctx.inject` is the only route that survives a host
 * providing it later. The
 * shape check is on the two methods this plugin actually calls — a partial
 * service must degrade to "no conversation" rather than throw on the first
 * alert of the day.
 */
function probeSessionController(ctx: ContextLike): () => SessionControllerLike | undefined {
  let svc: SessionControllerLike | undefined
  const set = (candidate: unknown): void => {
    const found = candidate as SessionControllerLike | undefined
    if (found && typeof found.create === 'function' && typeof found.prompt === 'function') svc = found
  }
  try {
    const reflect = (ctx as any).reflect
    if (reflect && typeof reflect.get === 'function') {
      set(reflect.get('sessionController'))
      set(reflect.get('sessionController', false))
    }
  } catch {
    /* ignore */
  }
  try {
    ctx.inject(['sessionController'], (sctx: any) => {
      try {
        set(sctx?.sessionController)
      } catch {
        /* ignore */
      }
    })
  } catch {
    /* ignore */
  }
  return () => svc
}

/** `withoutInitiator` is preferred; older hosts may not expose it. */
function withoutInitiator(ctx: ContextLike, fn: () => void): void {
  try {
    const agents = (ctx as any).agents
    if (agents && typeof agents.withoutInitiator === 'function') {
      agents.withoutInitiator(fn)
      return
    }
  } catch {
    /* fall through */
  }
  fn()
}

function activate(ctx: ContextLike, options?: Partial<Config>): void {
  const log = (level: 'warn' | 'info', message: string): void => {
    try {
      if (level === 'warn') ctx.logger?.warn(`${TAG} ${message}`)
      else ctx.logger?.info?.(`${TAG} ${message}`)
    } catch {
      /* ignore */
    }
  }

  const config = resolveConfig(options, readProfileDir(ctx))
  mkdirSync(config.dataDir, { recursive: true })

  const settings = new SettingsStore(config)
  settings.loadPersisted((message) => log('warn', message))

  const store = new AlertStore({
    dataDir: config.dataDir,
    ringSize: settings.current.ringSize,
    retentionDays: settings.current.retentionDays,
  })
  const pruned = store.prune()
  if (pruned) log('info', `清理过期告警文件 ${pruned} 个`)

  const stats = new StatsCounter()
  const sse = new SseHub()
  const token = randomBytes(24).toString('base64url')
  const getSessionController = probeSessionController(ctx)

  // ---- device roster (read-only, proxied from hillstone) ----------------------

  /**
   * Devices come from hillstone over loopback instead of a shared Cordis service.
   *
   * hillstone exports no service (its `provide(` count is zero), so a service
   * import is impossible without modifying an already-shipped plugin. Reading
   * its existing HTTP API keeps this plugin purely additive: nothing in
   * hillstone changes, and its regression suite stays untouched.
   *
   * Consequence worth stating: the list is cached for a few seconds, and device
   * passwords never touch this process at all.
   *
   * The port is discovered rather than hardcoded. hillstone's apiPort is a user
   * setting, so a fixed 18783 would report "zero devices" for anyone who moved
   * it — a pipeline that looks healthy and never maps a single source.
   */
  const OPS_DEFAULT_PORT = 18783
  const OPS_CANDIDATE_PORTS = [18783, 18785, 18786, 18787, 18782]
  let opsPort = settings.current.opsApiPort > 0 ? settings.current.opsApiPort : 0
  let opsBaseUrl = opsPort > 0 ? `http://127.0.0.1:${opsPort}` : ''

  async function probeOpsDeviceApi(port: number): Promise<unknown[] | undefined> {
    const resp = await fetch(`http://127.0.0.1:${port}/ops-api/devices`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(1500),
    }).catch(() => undefined)
    if (!resp || !resp.ok) return undefined
    const json = (await resp.json().catch(() => undefined)) as { ok?: boolean; devices?: unknown[] } | undefined
    if (!json || json.ok !== true || !Array.isArray(json.devices)) return undefined
    return json.devices
  }

  /** Returns the raw device list, or undefined when nothing answered. */
  async function discoverOpsApi(): Promise<{ port: number; devices: unknown[] } | undefined> {
    const configured = settings.current.opsApiPort
    const candidates = configured > 0 ? [configured] : OPS_CANDIDATE_PORTS
    for (const port of candidates) {
      const devices = await probeOpsDeviceApi(port)
      if (devices) return { port, devices }
    }
    return undefined
  }

  let deviceCache: { at: number; devices: DeviceLike[] } | undefined
  async function fetchDevices(): Promise<DeviceLike[]> {
    const now = Date.now()
    if (deviceCache && now - deviceCache.at < 5000) return deviceCache.devices
    const found = await discoverOpsApi().catch(() => undefined)
    if (!found) {
      // An unreachable hillstone must not be fatal: alerts still arrive and
      // still show up; they just stay unmapped, which prefilter already handles.
      const cached = deviceCache?.devices
      if (cached) return cached
      if (settings.current.opsApiPort > 0) {
        log('warn', `配置的 hillstone 端口 ${settings.current.opsApiPort} 无响应（/ops-api/devices），告警将标记为未映射`)
      } else {
        log('warn', `未找到 hillstone 的 /ops-api（已尝试 ${OPS_CANDIDATE_PORTS.join('/')}），告警将标记为未映射`)
      }
      deviceCache = { at: now, devices: [] }
      return []
    }
    if (found.port !== opsPort) {
      opsPort = found.port
      opsBaseUrl = `http://127.0.0.1:${found.port}`
      log('info', `已发现 hillstone 运维 API：http://127.0.0.1:${found.port}`)
    }
    const devices = (found.devices ?? [])
      .map((d) => d as Record<string, unknown>)
      .filter((d) => typeof d.id === 'string')
      .map((d) => ({
        id: d.id as string,
        name: typeof d.name === 'string' ? d.name : undefined,
        ip: typeof d.ip === 'string' ? d.ip : undefined,
        // hillstone Device has no syslogFrom/syslogCidrs fields, so a device
        // whose syslog source differs from its SSH address needs a manual
        // mapping. Until then the ip match is the best available identity.
        syslogFrom: undefined,
        syslogCidrs: undefined,
      }))
    deviceCache = { at: now, devices }
    return devices
  }

  // ---- storm / rate limiting -------------------------------------------------

  /** fingerprint → { alertId, windowStart, count }. */
  const dedupTable = new Map<string, { alertId: string; windowStart: number; count: number }>()
  /** deviceId → per-minute frame counter. */
  const rateTable = new Map<string, { minuteStart: number; count: number }>()

  // Two wrappers: one returns a value, the other exists only to hand a
  // throwing background job to the initiator guard.
  function withoutInitiator2<T>(fn: () => Promise<T>): Promise<T> {
    try {
      const agents = (ctx as any).agents
      if (agents && typeof agents.withoutInitiator === 'function') {
        return Promise.resolve(agents.withoutInitiator(fn) as Promise<T>)
      }
    } catch {
      /* fall through */
    }
    return fn()
  }

  // ---- frame intake ----------------------------------------------------------

  function onFrame(frame: ReceivedFrame): void {
    const cfg = settings.current
    stats.inc('received')
    const message = parseSyslogFrame(frame.text, frame.at)

    void handleFrameAsync(message, frame, cfg).catch((err) => {
      log('warn', `处理帧失败：${err instanceof Error ? err.message : String(err)}`)
    })
  }

  async function handleFrameAsync(message: SyslogMessage, frame: ReceivedFrame, cfg: Config): Promise<void> {
    const devices = await fetchDevices()
    const mapping = mapSourceToDevice(frame.sourceIp ?? '', devices)
    const verdict = prefilter(message, mapping, cfg, frame.at)

    if (verdict.drop) {
      stats.inc('filtered')
      return
    }

    const fp = fingerprint(mapping.deviceId, message)

    // Rate limit: cheap, and deliberately before dedup so a device that floods
    // with *varying* content cannot bypass it by changing its fingerprint.
    if (mapping.deviceId) {
      const minute = Math.floor(frame.at / 60_000)
      const cur = rateTable.get(mapping.deviceId)
      if (!cur || cur.minuteStart !== minute) {
        rateTable.set(mapping.deviceId, { minuteStart: minute, count: 1 })
      } else if (cur.count >= cfg.perDeviceRatePerMin) {
        cur.count += 1
        stats.inc('rateLimited')
        const existing = dedupTable.get(fp)
        if (existing) store.bumpRepeat(existing.alertId, frame.at)
        return
      } else {
        cur.count += 1
      }
    }

    // Dedup: one fingerprint inside the window collapses to one alert.
    const windowStart = frame.at - cfg.dedupWindowSec * 1000
    const hit = dedupTable.get(fp)
    if (hit && frame.at - hit.windowStart < cfg.dedupWindowSec * 1000) {
      hit.count += 1
      stats.inc('deduped')
      store.bumpRepeat(hit.alertId, frame.at)
      if (hit.count === cfg.stormThreshold) {
        stats.inc('storms')
        store.advance(hit.alertId, 'deduped', `已重复 ${hit.count} 次，升级为风暴聚合告警`)
        store.patch(hit.alertId, { fingerprint: `${fp}#storm` })
      } else if (hit.count > cfg.stormThreshold) {
        store.bumpRepeat(hit.alertId, frame.at)
      }
      return
    }

    const alert = store.create({
      receivedAt: frame.at,
      message,
      sourceIp: frame.sourceIp,
      sourcePort: frame.sourcePort,
      transport: frame.transport,
      deviceId: mapping.deviceId,
      deviceName: mapping.deviceName,
      fingerprint: fp,
    })
    stats.inc('alertsCreated')
    dedupTable.set(fp, { alertId: alert.id, windowStart, count: 1 })

    if (mapping.deviceId) {
      store.advance(alert.id, 'mapped', `来源 ${frame.sourceIp} → 设备 ${mapping.deviceName ?? mapping.deviceId}`)
    }
    if (verdict.storeOnly) {
      // Kept visible, never analysed. The reason travels to the UI verbatim so
      // "why did nothing happen?" is never a mystery.
      store.advance(alert.id, 'filtered', verdict.detail ?? '仅留存', undefined)
      store.patch(alert.id, { dropReason: verdict.reason as never })
      return
    }
    // Delivered after the record is complete: the store has the alert, the
    // mapping and the fingerprint, so the day-session agent sees a full row.
    postToAutoSession(alert)

    // Keep the tables from growing without bound on a long-lived host.
    if (dedupTable.size > 20_000) {
      const cutoff = frame.at - cfg.dedupWindowSec * 1000
      for (const [k, v] of dedupTable) if (v.windowStart < cutoff) dedupTable.delete(k)
    }
    if (rateTable.size > 5000) {
      const cutoff = Math.floor(frame.at / 60_000) - 2
      for (const [k, v] of rateTable) if (v.minuteStart < cutoff) rateTable.delete(k)
    }
  }

  // ---- the day's conversation (ordinary session) ------------------------------

  /**
   * One ordinary DSH session per day, fed by the incoming alerts.
   *
   * It asks the host's `sessionController` for an ordinary session: no subagent
   * provider to register, and nothing for the plugin to tear down — the host
   * persists the session and the operator opens it normally.
   *
   * Built with reactive getters, never a snapshot: `sessionController` appears
   * some time after activate(), and settings can change at any moment, so
   * capturing either at construction time would pin the runner to "no host
   * service, default settings" forever.
   */
  const autoSession = new AutoSessionRunner({
    get sessionController() {
      return getSessionController() as never
    },
    enabled: () => settings.current.autoSessionEnabled,
    titlePrefix: () => settings.current.autoSessionTitle,
    instruction: () => settings.current.autoSessionPrompt,
    workspacePath: () => settings.current.autoSessionWorkspace,
    dataDir: () => settings.current.dataDir,
    log,
    annotate: (id, ch) => store.annotate(id, ch),
  })

  function autoSessionStatus(): AutoSessionStatus {
    return autoSession.status()
  }

  function postToAutoSession(alert: Alert): void {
    if (!settings.current.autoSessionEnabled) return
    if (!getSessionController()) {
      // Reported through the runtime panel instead of once per alert: a host
      // without the service would otherwise fill the log during a storm.
      return
    }
    // Fire-and-forget: the alert already carries a Path A result, and awaiting a
    // multi-minute agent turn here would stall the syslog frame handler.
    void withoutInitiator2(() => autoSession.post(alert)).catch(() => undefined)
  }

  // ---- receiver --------------------------------------------------------------

  const receiver = new SyslogReceiver({
    config: settings.current,
    onFrame,
    onWarn: (message) => log('warn', message),
  })
  void receiver.start().then((st) => {
    if (st.boundPorts.length > 0) {
      log('info', `syslog 监听已就绪：UDP ${st.boundPorts.join(', ')}${st.transports.includes('tcp') ? ' + TCP' : ''}`)
    } else {
      log('warn', `syslog 监听未能绑定任何端口：${st.failedPorts.map((f) => `${f.port}(${f.reason})`).join('; ')}`)
    }
  })

  // ---- loopback API ----------------------------------------------------------

  const server = createServer((req, res) => {
    const send = (status: number, body: unknown): void => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify(body))
    }
    void (async () => {
      try {
        await handleApi(
          {
            config: () => settings.current,
            store,
            stats: () => stats.get(),
            listener: () => receiver.getStatus(),
            token,
            tokenEnabled: settings.current.apiTokenEnabled,
            devices: fetchDevices,
            onSettingsChanged: async (next: EditableSettings) => {
              const before = { ports: settings.current.syslogPorts, tcp: settings.current.enableTcp }
              settings.apply(next)
              if (JSON.stringify(before.ports) !== JSON.stringify(settings.current.syslogPorts) || before.tcp !== settings.current.enableTcp) {
                await receiver.restart()
              }
            },
            ack: (id) => {
              store.ack(id)
            },
            injectFrame: async (text, sourceIp) => {
              onFrame({ text, sourceIp, sourcePort: 0, transport: 'udp', at: Date.now() })
            },
            listenerControl: async (action) => {
              try {
                if (action === 'stop') {
                  // `stop()` resolves void; the status has to be read afterwards.
                  await receiver.stop()
                  log('info', 'syslog 监听已停止')
                  return { ok: true, status: receiver.getStatus() }
                }
                const status = await receiver.start()
                log(
                  'info',
                  status.boundPorts.length > 0
                    ? `syslog 监听已启动：UDP ${status.boundPorts.join(', ')}${status.transports.includes('tcp') ? ' + TCP' : ''}`
                    : `syslog 监听未能绑定任何端口：${status.failedPorts.map((f) => `${f.port}(${f.reason})`).join('; ')}`,
                )
                return { ok: true, status }
              } catch (err) {
                const error = err instanceof Error ? err.message : String(err)
                log('warn', `${action === 'stop' ? '停止' : '启动'} syslog 监听失败：${error}`)
                return { ok: false, status: receiver.getStatus(), error }
              }
            },
            autoSession: autoSessionStatus,
            log,
          },
          req,
          res,
          sse,
        )
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        log('warn', `api error: ${message}`)
        if (!res.headersSent) send(500, { ok: false, error: { code: 'internal', message } })
      }
    })()
  })

  server.once('error', (e: Error) => log('warn', `loopback server on :${settings.current.apiPort} failed: ${e.message}`))
  server.listen(settings.current.apiPort, '127.0.0.1', () => {
    log('info', `API listening at http://127.0.0.1:${settings.current.apiPort}${API_PREFIX}`)
  })

  // Fan every store change out to connected panels.
  const unsubscribe = store.subscribe((alert, kind) => {
    sse.send(kind === 'created' ? 'alert' : 'update', { alert })
  })

  // ---- agent tools -----------------------------------------------------------

  function tryRegisterTools(tctx: any): void {
    const registry = tctx.tools
    if (!registry || typeof registry.register !== 'function') return

    const failure = (value: unknown): string | undefined =>
      value && typeof value === 'object' && (value as { ok?: boolean }).ok === false
        ? `执行失败：${(value as { error?: string }).error ?? '未知错误'}`
        : undefined

    const toolOutput = (render: (v: any) => string, schema: Record<string, unknown> = { type: 'object' }) => ({
      schema,
      render(_args: unknown, value: unknown) {
        let text: string
        try {
          // The failure check lives HERE rather than in each render closure: a
          // closure that forgets it prints a success-shaped empty body and the
          // model reads that as "no alerts found" rather than "the query failed".
          const bad = failure(value)
          text = bad ?? render(value)
        } catch {
          text = typeof value === 'string' ? value : JSON.stringify(value)
        }
        return [{ type: 'text', text }]
      },
    })

    const fmtTime = (ms: number): string => new Date(ms).toLocaleString('zh-CN', { hour12: false })

    const listDef = {
      name: 'syslog_alerts',
      description:
        '查询智能告警中心里的告警列表。这是发现告警的入口。' +
        '参数：severityMax（可选，0-7，只返回严重度<=该值的告警，越小越严重）、' +
        'deviceId（可选，按设备过滤，先用本工具的返回里的 deviceId）、' +
        'stage（可选，received/mapped/filtered/deduped/closed/failed）、' +
        'sinceMinutes（可选，只看最近 N 分钟）、q（可选，在原始日志/标签/设备名里搜关键字）、' +
        'limit（可选，默认 20）。返回告警摘要列表，detail 用 syslog_alert_detail 展开。',
      // `parameters` must be the WIRE-LEVEL JSON Schema, not the `defineTool` author
      // DSL: `ctx.tools.register()` only validates `output.schema` and copies
      // `parameters` onto the model-facing schema verbatim (see dsh-tools
      // lib/index.js `register()` + `schemaOf()`), so a flat author map reaches the
      // provider without a `type` and is rejected as `got 'type: null'`.
      // The wire subset is type/oneOf/properties/required/additionalProperties/
      // items/enum/const + description/title/default/examples — numeric bounds are
      // NOT part of it, so they live in the descriptions (execute() clamps too).
      parameters: {
        type: 'object',
        properties: {
          severityMax: { type: 'integer', description: '只看严重度 <= 该值的告警（0=emerg 最严重，取值范围 0-7）' },
          deviceId: { type: 'string', description: '只看该设备的告警' },
          stage: { type: 'string', enum: ['received', 'mapped', 'filtered', 'deduped', 'closed', 'failed'], description: '只看处于该分析阶段的告警' },
          sinceMinutes: { type: 'integer', description: '只看最近 N 分钟内的告警（1-10080，即最多 7 天）' },
          q: { type: 'string', description: '在原始日志文本、mnemonic 标签或设备名中搜索' },
          limit: { type: 'integer', description: '返回条数上限（1-200），默认 20' },
        },
      },
      output: toolOutput((v: any) => {
        if (!v.alerts?.length) return '没有匹配的告警。'
        const lines = [`共 ${v.total} 条告警，返回最近 ${v.alerts.length} 条：`, '']
        for (const a of v.alerts) {
          lines.push(
            `- [${a.severityName ?? '?'}${a.count > 1 ? ` ×${a.count}` : ''}] ${a.deviceName ?? '未映射设备'} ${a.tag ?? ''} @ ${fmtTime(a.receivedAt)}`,
          )
          lines.push(`  id=${a.id} stage=${a.stage}`)
          lines.push(`  ${a.excerpt}`)
        }
        lines.push('', '用 syslog_alert_detail 展开某条告警的完整时间线。')
        return lines.join('\n')
      }),
      async execute(args: { severityMax?: number; deviceId?: string; stage?: never; sinceMinutes?: number; q?: string; limit?: number }) {
        const { alerts, total } = store.list({
          severityMax: args.severityMax,
          deviceId: args.deviceId,
          stage: args.stage,
          sinceMs: args.sinceMinutes ? Date.now() - args.sinceMinutes * 60_000 : undefined,
          search: args.q,
          limit: Math.min(args.limit ?? 20, 200),
        })
        return {
          ok: true,
          total,
          alerts: alerts.map((a) => ({
            id: a.id,
            receivedAt: a.receivedAt,
            stage: a.stage,
            severity: a.message.severity,
            severityName: a.message.severityName,
            tag: a.message.tag,
            deviceId: a.deviceId,
            deviceName: a.deviceName,
            count: a.count,
            excerpt: a.message.message.slice(0, 200),
          })),
        }
      },
    }

    const detailDef = {
      name: 'syslog_alert_detail',
      description:
        '取一条告警的完整分析时间线：原始 syslog、解析可信度、当日会话 agent 的分析结论。参数：id（先用 syslog_alerts 拿到）。',
      parameters: {
        type: 'object',
        properties: { id: { type: 'string', description: '告警 id（先用 syslog_alerts 拿到）' } },
        required: ['id'],
      },
      output: toolOutput((v: any) => {
        if (!v.alert) return '告警不存在或已过期。'
        const a = v.alert
        const lines: string[] = []
        lines.push(`告警 ${a.id}`)
        lines.push(`时间：${fmtTime(a.receivedAt)}  来源：${a.sourceIp ?? '?'}  传输：${a.transport ?? '?'}`)
        lines.push(`设备：${a.deviceName ?? '未映射'}（${a.deviceId ?? '-'}）`)
        lines.push(`解析可信度：${a.message.confidence}  级别：${a.message.severityName ?? '?'}  重复次数：${a.count}`)
        lines.push('')
        lines.push('【原始 syslog】')
        lines.push(a.message.raw)
        if (a.dropReason) {
          lines.push('')
          lines.push(`【未进入分析】${a.dropDetail ?? a.dropReason}`)
        }
        if (a.analysisPending) {
          lines.push('')
          lines.push('【会话分析】当日会话 agent 正在分析中，结论写回后将在此显示。')
        }
        if (a.sessionConclusion) {
          lines.push('')
          lines.push(`【当日会话分析结论】${a.sessionConclusionAt ? `（提取于 ${fmtTime(a.sessionConclusionAt)}）` : ''}`)
          lines.push(a.sessionConclusion)
        }
        return lines.join('\n')
      }),
      async execute(args: { id: string }) {
        const alert = store.get(args.id)
        if (!alert) return { ok: false, error: '告警不存在或已过期' }
        return { ok: true, alert }
      },
    }

    const statsDef = {
      name: 'syslog_stats',
      description:
        '返回 syslog 接收的运行统计：监听端口与状态、收到/创建/去重/限流/丢弃的条数。排查「设备日志没进来」或「告警没有结论」时先看它。参数：无。',
      parameters: { type: 'object', properties: {} },
      output: toolOutput((v: any) => {
        const s = v.stats
        const l = v.listener
        const lines = [
          `监听：${l.listening ? '运行中' : '未运行'}  端口：${l.boundPorts.length ? l.boundPorts.join(', ') : '无'}  传输：${l.transports.join('+') || '无'}`,
        ]
        if (l.failedPorts.length) lines.push(`绑定失败：${l.failedPorts.map((f: { port: number; reason: string }) => `${f.port} → ${f.reason}`).join('; ')}`)
        lines.push(`收包：${l.packets}  建立告警：${s.alertsCreated}  预过滤丢弃：${s.filtered}`)
        lines.push(`去重：${s.deduped}  限流：${s.rateLimited}  风暴聚合：${s.storms}`)
        if (l.listening && l.packets === 0) {
          lines.push('')
          lines.push('注意：监听已启动但一个包都没收到。检查设备侧 syslog server 地址与端口、以及本机防火墙是否放行入站。')
        }
        return lines.join('\n')
      }),
      async execute() {
        return { ok: true, stats: stats.get(), listener: receiver.getStatus() }
      },
    }

    // The day-session agent analyses each alert inside the operator's ordinary
    // session. We never read that transcript back (not a documented surface), so
    // the prompt instructs the agent to call THIS tool with its conclusion. It
    // writes the conclusion onto the alert and clears the pending flag; without
    // it the UI would spin "会话分析中" forever.
    const concludeDef = {
      name: 'syslog_conclude',
      description:
        '把你对某条告警的分析结论写回智能告警中心。当日会话分析完一条告警后必须调用本工具，否则结论不会显示给用户。参数：alertId（告警 id）、conclusion（你的完整分析结论，可多行）。',
      parameters: {
        type: 'object',
        properties: {
          alertId: { type: 'string', description: '告警 id（来自「分析这条日志」提示词开头，格式 告警 id：xxx）' },
          conclusion: { type: 'string', description: '针对该告警的完整分析结论，可包含多行与要点列表' },
        },
        required: ['alertId', 'conclusion'],
      },
      output: toolOutput((v: any) => (v.ok ? `已将结论写回告警 ${v.id}。` : `写回失败：${v.error}`)),
      async execute(args: { alertId: string; conclusion: string }) {
        const alert = store.get(args.alertId)
        if (!alert) return { ok: false, error: '告警不存在或已过期' }
        store.annotate(args.alertId, { conclusion: String(args.conclusion ?? '') })
        return { ok: true, id: args.alertId }
      },
    }

    const unregister = registry.register(listDef)
    const unregisterDetail = registry.register(detailDef)
    const unregisterStats = registry.register(statsDef)
    const unregisterConclude = registry.register(concludeDef)
    void unregister
    void unregisterDetail
    void unregisterStats
    void unregisterConclude
  }

  try {
    ctx.inject(['tools'], (tctx: any) => {
      tctx.effect(() => {
        try {
          tryRegisterTools(tctx)
        } catch (e) {
          // A half-registered tool surface is invisible in the UI and the agent
          // then reports it "cannot read alerts" with no clue why. Leave a
          // breadcrumb in the one place an operator will actually look.
          log('warn', `工具注册失败：${(e as Error).message}`)
          try {
            appendFileSync(
              join(config.dataDir, 'plugin-errors.log'),
              `[${new Date().toISOString()}] tool registration failed: ${(e as Error).message}\n`,
            )
          } catch {
            /* diagnostics must never break activation */
          }
        }
      }, `${name}: tools`)
    })
  } catch {
    /* ignore */
  }

  // ---- teardown --------------------------------------------------------------

  const eff = (ctx as any).effect
  if (typeof eff === 'function') {
    eff.call(
      ctx,
      () => () => {
        unsubscribe()
        sse.closeAll()
        void receiver.stop()
        // Only drops the cached day reference: the host owns this session, so
        // there is nothing to tear down and the conversation stays readable.
        autoSession.dispose()
        try {
          server.close()
        } catch {
          /* ignore */
        }
        dedupTable.clear()
        rateTable.clear()
      },
      `${name}: syslog receiver + loopback api`,
    )
  }
}

export function apply(ctx: ContextLike, config?: Partial<Config>): void {
  try {
    activate(ctx, config)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    try {
      ctx.logger?.warn(`${TAG} activation degraded: ${message}`)
    } catch {
      /* ignore */
    }
  }
}

export { DEFAULT_CONFIG, resolveConfig }
export { originIsLocalOrAbsent, splitFrames }
export { drainTcpBuffer, tcpDrainedLength } from './syslog-server.ts'