// dsh-syslog-alert — loopback HTTP API (client ↔ host bridge).
//
// Mirrors dsh-hillstone-cli-ops' /ops-api and dsh-knowledge-base's /kb-api:
// a fixed loopback port, CORS, and a token that is only demanded from a
// genuinely remote Origin. Same reasoning as the sibling plugin — requiring the
// token for same-loopback callers would leave the panel with no bootstrap path.
//
// Two things differ from a plain CRUD API and drive the shape below:
//   - a live SSE stream, because the whole point is watching alerts arrive;
//   - a device list proxied from hillstone, so this plugin never has to know
//     where the hillstone store lives on disk.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { Config, EditableSettings, ListenerStatus, Stats } from './types.ts'
import type { AlertStore } from './alert-store.ts'
import type { DeviceLike } from './fingerprint.ts'

export const API_PREFIX = '/syslog-api'

export interface ApiDeps {
  config: () => Config
  store: AlertStore
  stats: () => Stats
  listener: () => ListenerStatus
  token: string
  tokenEnabled: boolean
  devices: () => Promise<DeviceLike[]>
  onSettingsChanged: (next: EditableSettings) => Promise<void>
  ack: (id: string) => void
  /** Feed a synthetic frame through the real pipeline (self-test button). */
  injectFrame: (text: string, sourceIp?: string) => Promise<void>
  /** Start / stop the syslog sockets without unloading the plugin. */
  listenerControl: (action: 'start' | 'stop') => Promise<{ ok: boolean; status: ListenerStatus; error?: string }>
  /**
   * The day's ordinary session, if the host offers `sessionController`.
   *
   * Optional because it is a convenience view, not part of the pipeline: a
   * host without the service leaves the panel showing the reason from status()
   * instead of a value, and nothing else in the API depends on it.
   */
  autoSession?: () => unknown
  log: (level: 'warn' | 'info', message: string) => void
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(text)
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c) => chunks.push(c as Buffer))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')))
    req.on('error', reject)
  })
}

/**
 * The DSH desktop app serves the frontend from the `dsh-app:` scheme, not from
 * 127.0.0.1, so its panel requests carry `Origin: dsh-app://app` and have no
 * loopback hostname. Treating that as "remote" would 401 every write with no
 * visible reaction, so the scheme is allowed explicitly.
 */
export function originIsLocalOrAbsent(req: IncomingMessage): boolean {
  const raw = req.headers['origin']
  const origin = Array.isArray(raw) ? raw[0] : raw
  if (!origin) return true
  if (origin === 'null') return true
  try {
    const url = new URL(origin)
    if (url.protocol === 'dsh-app:') return true
    const { hostname } = url
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname === '[::1]' ||
      hostname.endsWith('.localhost')
    )
  } catch {
    return false
  }
}

function intParam(url: URL, key: string): number | undefined {
  const v = url.searchParams.get(key)
  if (v === null) return undefined
  const n = Number(v)
  return Number.isFinite(n) ? n : undefined
}

/** SSE subscriber registry. One entry per open panel connection. */
export class SseHub {
  private clients = new Set<ServerResponse>()

  add(res: ServerResponse): () => void {
    this.clients.add(res)
    // A proxy between here and the browser can idle the socket out; a periodic
    // comment keeps it warm without touching the event stream.
    const keepalive = setInterval(() => {
      try {
        res.write(': keepalive\n\n')
      } catch {
        /* ignore */
      }
    }, 25_000)
    keepalive.unref?.()
    return () => {
      clearInterval(keepalive)
      this.clients.delete(res)
    }
  }

  send(event: string, data: unknown): void {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`
    for (const res of this.clients) {
      try {
        res.write(payload)
      } catch {
        this.clients.delete(res)
      }
    }
  }

  get size(): number {
    return this.clients.size
  }

  closeAll(): void {
    for (const res of this.clients) {
      try {
        res.end()
      } catch {
        /* ignore */
      }
    }
    this.clients.clear()
  }
}

export async function handleApi(deps: ApiDeps, req: IncomingMessage, res: ServerResponse, sse: SseHub): Promise<void> {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Syslog-Token')
  res.setHeader('Access-Control-Max-Age', '300')
  if (req.method === 'OPTIONS') {
    res.statusCode = 204
    res.end()
    return
  }

  const url = new URL(req.url ?? '/', 'http://dsh.internal')
  const pathname = url.pathname.startsWith(API_PREFIX) ? url.pathname.slice(API_PREFIX.length) : url.pathname
  const method = req.method ?? 'GET'

  if (deps.tokenEnabled && pathname !== '/_session' && method !== 'OPTIONS' && !originIsLocalOrAbsent(req)) {
    const raw = req.headers['x-syslog-token']
    // EventSource cannot set request headers, so the SSE route is the one place
    // a token may arrive as a query parameter. It is restricted to that route:
    // accepting it everywhere would put a long-lived credential in access logs
    // and browser history for every ordinary request.
    const queryToken = pathname === '/alerts/stream' ? url.searchParams.get('token') : null
    const provided = ((Array.isArray(raw) ? raw[0] : raw) || queryToken || '').trim()
    if (provided !== deps.token) {
      writeJson(res, 401, { ok: false, error: { code: 'unauthorized', message: '缺少或无效的智能告警中心访问令牌（X-Syslog-Token）' } })
      return
    }
  }

  if (method === 'GET') {
    if (pathname === '/_session') {
      const local = originIsLocalOrAbsent(req)
      writeJson(res, 200, { ok: true, enabled: deps.tokenEnabled, token: local && deps.tokenEnabled ? deps.token : '', local })
      return
    }
    if (pathname === '/status') {
      const cfg = deps.config()
      writeJson(res, 200, {
        ok: true,
        listener: deps.listener(),
        stats: deps.stats(),
        config: {
          apiPort: cfg.apiPort,
          syslogPorts: cfg.syslogPorts,
          enableTcp: cfg.enableTcp,
          unmappedPolicy: cfg.unmappedPolicy,
          minSeverity: cfg.minSeverity,
          mnemonicAllow: cfg.mnemonicAllow,
          dedupWindowSec: cfg.dedupWindowSec,
          perDeviceRatePerMin: cfg.perDeviceRatePerMin,
          stormThreshold: cfg.stormThreshold,
          autoSessionEnabled: cfg.autoSessionEnabled,
          autoSessionTitle: cfg.autoSessionTitle,
          autoSessionWorkspace: cfg.autoSessionWorkspace,
          autoSessionPrompt: cfg.autoSessionPrompt,
          retentionDays: cfg.retentionDays,
          maintenanceWindows: cfg.maintenanceWindows,
        },
        devices: await deps.devices(),
        autoSession: deps.autoSession?.() ?? null,
        sseClients: sse.size,
      })
      return
    }
    if (pathname === '/stats') {
      writeJson(res, 200, { ok: true, stats: deps.stats(), listener: deps.listener() })
      return
    }
    if (pathname === '/auto-session') {
      writeJson(res, 200, { ok: true, autoSession: deps.autoSession?.() ?? null })
      return
    }
    if (pathname === '/alerts') {
      const { alerts, total } = deps.store.list({
        severityMax: intParam(url, 'severityMax'),
        deviceId: url.searchParams.get('deviceId') ?? undefined,
        stage: (url.searchParams.get('stage') as never) ?? undefined,
        sinceMs: intParam(url, 'since'),
        search: url.searchParams.get('q') ?? undefined,
        limit: intParam(url, 'limit'),
        offset: intParam(url, 'offset'),
      })
      writeJson(res, 200, { ok: true, alerts, total })
      return
    }
    if (pathname === '/alerts/stream') {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      })
      res.write('retry: 3000\n\n')
      const off = sse.add(res)
      req.on('close', off)
      req.on('error', off)
      return
    }
    // /alerts/:id
    const detailMatch = /^\/alerts\/([^/]+)$/.exec(pathname)
    if (detailMatch) {
      const alert = deps.store.get(decodeURIComponent(detailMatch[1] as string))
      if (!alert) {
        writeJson(res, 404, { ok: false, error: { code: 'not-found', message: '告警不存在或已过期' } })
        return
      }
      writeJson(res, 200, { ok: true, alert })
      return
    }
    writeJson(res, 404, { ok: false, error: { code: 'not-found', message: 'unknown syslog-api route' } })
    return
  }

  if (method === 'POST' || method === 'PUT') {
    if (pathname === '/settings') {
      let body: EditableSettings
      try {
        body = JSON.parse((await readBody(req)) || '{}') as EditableSettings
      } catch {
        writeJson(res, 400, { ok: false, error: { code: 'bad-request', message: 'settings 必须是 JSON' } })
        return
      }
      try {
        await deps.onSettingsChanged(body)
        writeJson(res, 200, { ok: true })
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        writeJson(res, 400, { ok: false, error: { code: 'bad-request', message } })
      }
      return
    }
    if (pathname === '/test-alert') {
      // Injects a synthetic frame so the operator can verify the whole chain
      // (listener status, mapping, prefilter, analysis, UI) without touching a
      // real device. It goes through the identical onFrame path a datagram
      // takes — a self-test that used a side door would pass while the real
      // receiver is broken.
      let body: { message?: string; sourceIp?: string }
      try {
        body = JSON.parse((await readBody(req)) || '{}') as { message?: string; sourceIp?: string }
      } catch {
        writeJson(res, 400, { ok: false, error: { code: 'bad-request', message: 'body 必须是 JSON' } })
        return
      }
      const text = (body.message ?? '').trim()
      if (!text) {
        writeJson(res, 400, { ok: false, error: { code: 'bad-request', message: '缺少 message' } })
        return
      }
      await deps.injectFrame(text, body.sourceIp)
      writeJson(res, 200, { ok: true, injected: text, sourceIp: body.sourceIp ?? null })
      return
    }
    if (pathname === '/listener') {
      // Stopping the sockets is a distinct action from disabling the plugin:
      // the panel, the tools and the stored alerts all stay available, which is
      // what an operator wants when they need the port back for something else.
      let action: 'start' | 'stop' = 'start'
      try {
        const parsed = JSON.parse((await readBody(req)) || '{}') as { action?: string }
        if (parsed.action !== 'start' && parsed.action !== 'stop') {
          writeJson(res, 400, { ok: false, error: { code: 'bad-request', message: 'action 必须是 start 或 stop' } })
          return
        }
        action = parsed.action
      } catch {
        writeJson(res, 400, { ok: false, error: { code: 'bad-request', message: 'body 必须是 JSON' } })
        return
      }
      const result = await deps.listenerControl(action)
      writeJson(res, result.ok ? 200 : 409, { ok: result.ok, status: result.status, error: result.error ?? null })
      return
    }
    const ackMatch = /^\/alerts\/([^/]+)\/ack$/.exec(pathname)
    if (ackMatch) {
      deps.ack(decodeURIComponent(ackMatch[1] as string))
      writeJson(res, 200, { ok: true })
      return
    }
  }

  writeJson(res, 405, { ok: false, error: { code: 'method-not-allowed', message: method } })
}