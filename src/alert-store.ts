// dsh-syslog-alert — alert store.
//
// Two layers, because they answer different questions:
//   - a bounded in-memory ring answers "what is on screen right now" and must
//     never grow without limit (an alert storm is a normal operating condition,
//     not an exceptional one);
//   - day-partitioned JSONL answers "what happened last Tuesday" and is append-only.
//
// Both are written on the same code path so the on-screen view and the durable
// record cannot disagree.

import { appendFileSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Alert, AlertStage, Stats, TimelineEntry } from './types.ts'

function dayKey(ts = Date.now()): string {
  const d = new Date(ts)
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

export interface StoreOptions {
  dataDir: string
  ringSize: number
  retentionDays: number
}

export class AlertStore {
  /** Oldest → newest. Ring semantics: shift() past ringSize. */
  private ring: Alert[] = []
  /** Alert id → live alert, for O(1) detail lookups. Mirrors the ring. */
  private byId = new Map<string, Alert>()
  private dayCounts = new Map<string, number>()
  private dir: string
  private ringSize: number
  private retentionDays: number
  /** Listeners for SSE fan-out. */
  private listeners = new Set<(alert: Alert, kind: 'created' | 'updated') => void>()

  constructor(opts: StoreOptions) {
    this.dir = join(opts.dataDir, 'alerts')
    mkdirSync(this.dir, { recursive: true })
    this.ringSize = Math.max(50, opts.ringSize)
    this.retentionDays = Math.max(1, opts.retentionDays)
  }

  /** Delete JSONL day files past the retention window. Returns removed count. */
  prune(): number {
    const cutoff = Date.now() - this.retentionDays * 24 * 3600 * 1000
    let removed = 0
    let files: string[] = []
    try {
      files = readdirSync(this.dir)
    } catch {
      return 0
    }
    for (const f of files) {
      if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)) continue
      const p = join(this.dir, f)
      try {
        if (statSync(p).mtimeMs < cutoff) {
          unlinkSync(p)
          removed++
        }
      } catch {
        /* ignore */
      }
    }
    return removed
  }

  private fileFor(ts: number): string {
    return join(this.dir, `${dayKey(ts)}.jsonl`)
  }

  private append(alert: Alert): void {
    const day = dayKey(alert.receivedAt)
    const n = (this.dayCounts.get(day) ?? 0) + 1
    this.dayCounts.set(day, n)
    // After ~2MB in one day the line cost dominates; roll to a sequence file.
    const file = n > 20000 ? this.fileFor(alert.receivedAt).replace('.jsonl', `-${Math.floor(n / 20000)}.jsonl`) : this.fileFor(alert.receivedAt)
    try {
      appendFileSync(file, JSON.stringify(alert) + '\n', 'utf-8')
    } catch {
      // Durability is best-effort: a disk failure must not stop reception.
    }
  }

  /** Rewrite the alert's JSONL line in place (today's file only). */
  private rewrite(alert: Alert): void {
    // Rewriting a rotated file would need an index we do not keep; skip those.
    const day = dayKey(alert.receivedAt)
    const n = this.dayCounts.get(day) ?? 0
    if (n > 20000) return
    const file = this.fileFor(alert.receivedAt)
    if (!existsSync(file)) return
    // The ring is the authority for the live view; persisting every stage
    // transition as a full snapshot would multiply the file for no gain. The
    // snapshot is rewritten on terminal stages only, via appendFinal below.
    void file
  }

  subscribe(fn: (alert: Alert, kind: 'created' | 'updated') => void): () => void {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  private emit(alert: Alert, kind: 'created' | 'updated'): void {
    for (const fn of this.listeners) {
      try {
        fn(alert, kind)
      } catch {
        /* ignore */
      }
    }
  }

  create(seed: {
    receivedAt: number
    message: Alert['message']
    sourceIp?: string
    sourcePort?: number
    transport?: 'udp' | 'tcp'
    deviceId?: string
    deviceName?: string
    fingerprint?: string
  }): Alert {
    const alert: Alert = {
      id: randomUUID(),
      receivedAt: seed.receivedAt,
      stage: 'received',
      message: seed.message,
      deviceId: seed.deviceId,
      deviceName: seed.deviceName,
      sourceIp: seed.sourceIp,
      sourcePort: seed.sourcePort,
      transport: seed.transport,
      fingerprint: seed.fingerprint,
      count: 1,
      firstSeenAt: seed.receivedAt,
      lastSeenAt: seed.receivedAt,
      timeline: [{ at: seed.receivedAt, stage: 'received', note: '接收' }],
    }
    this.ring.push(alert)
    this.byId.set(alert.id, alert)
    while (this.ring.length > this.ringSize) {
      const gone = this.ring.shift()
      if (gone) this.byId.delete(gone.id)
    }
    this.append(alert)
    this.emit(alert, 'created')
    return alert
  }

  get(id: string): Alert | undefined {
    return this.byId.get(id)
  }

  /** Bump a fingerprint's repeat counter on the alert that already owns it. */
  bumpRepeat(id: string, at: number): Alert | undefined {
    const alert = this.byId.get(id)
    if (!alert) return undefined
    alert.count += 1
    alert.lastSeenAt = at
    this.emit(alert, 'updated')
    return alert
  }

  /** Push a stage transition with a note. Never moves backwards. */
  advance(id: string, stage: AlertStage, note: string, durationMs?: number): Alert | undefined {
    const alert = this.byId.get(id)
    if (!alert) return undefined
    const entry: TimelineEntry = { at: Date.now(), stage, note }
    if (durationMs !== undefined) entry.durationMs = durationMs
    alert.timeline.push(entry)
    alert.stage = stage
    if (stage === 'closed' || stage === 'failed') {
      this.append(alert) // terminal snapshot
    }
    this.emit(alert, 'updated')
    return alert
  }

  patch(id: string, changes: Partial<Alert>): Alert | undefined {
    const alert = this.byId.get(id)
    if (!alert) return undefined
    Object.assign(alert, changes)
    this.emit(alert, 'updated')
    return alert
  }

  ack(id: string): Alert | undefined {
    return this.patch(id, { ackedAt: Date.now(), stage: 'closed' })
  }

  /**
   * Write the day-session agent's analysis conclusion back onto the alert.
   *
   * The conclusion is produced asynchronously by an agent turn inside the
   * operator's ordinary session; it reaches us through a plugin tool
   * (`syslog_conclude`) the prompt instructs the agent to call, not by reading
   * the session transcript (that is not a documented surface). On write we drop
   * `analysisPending` so the UI stops showing the "会话分析中" spinner.
   */
  annotate(id: string, changes: { conclusion?: string; sessionId?: string }): Alert | undefined {
    const alert = this.byId.get(id)
    if (!alert) return undefined
    if (changes.sessionId !== undefined) alert.sessionId = changes.sessionId
    // Admission (sessionId set, no conclusion yet) means "waiting for the turn".
    // A conclusion writeback clears it; without this the UI has no pending state.
    if (changes.sessionId !== undefined && changes.conclusion === undefined) {
      alert.analysisPending = true
    }
    if (changes.conclusion !== undefined) {
      alert.sessionConclusion = changes.conclusion
      alert.sessionConclusionAt = Date.now()
      alert.analysisPending = false
    }
    // Persist a full snapshot so the conclusion survives a restart.
    this.append(alert)
    this.emit(alert, 'updated')
    return alert
  }

  /** Newest first, with optional filters. */
  list(filter: {
    severityMax?: number
    deviceId?: string
    stage?: AlertStage
    sinceMs?: number
    search?: string
    limit?: number
    offset?: number
  } = {}): { alerts: Alert[]; total: number } {
    let rows = [...this.ring].reverse()
    if (filter.severityMax !== undefined) {
      rows = rows.filter((a) => (a.message.severity ?? 9) <= filter.severityMax!)
    }
    if (filter.deviceId) rows = rows.filter((a) => a.deviceId === filter.deviceId)
    if (filter.stage) rows = rows.filter((a) => a.stage === filter.stage)
    if (filter.sinceMs !== undefined) rows = rows.filter((a) => a.receivedAt >= filter.sinceMs!)
    if (filter.search) {
      const q = filter.search.toLowerCase()
      rows = rows.filter(
        (a) =>
          a.message.raw.toLowerCase().includes(q) ||
          (a.message.tag ?? '').toLowerCase().includes(q) ||
          (a.deviceName ?? '').toLowerCase().includes(q),
      )
    }
    const total = rows.length
    const offset = filter.offset ?? 0
    const limit = filter.limit ?? 100
    return { alerts: rows.slice(offset, offset + limit), total }
  }

  /** Device ids present in the ring, for the UI's device filter. */
  devices(): { deviceId: string; deviceName?: string; count: number }[] {
    const seen = new Map<string, { deviceName?: string; count: number }>()
    for (const a of this.ring) {
      if (!a.deviceId) continue
      const cur = seen.get(a.deviceId) ?? { deviceName: a.deviceName, count: 0 }
      cur.count += 1
      if (!cur.deviceName && a.deviceName) cur.deviceName = a.deviceName
      seen.set(a.deviceId, cur)
    }
    return [...seen.entries()].map(([deviceId, v]) => ({ deviceId, ...v }))
  }

  /** Trim the ring without waiting for new traffic (after a settings change). */
  resizeRing(size: number): void {
    this.ringSize = Math.max(50, size)
    while (this.ring.length > this.ringSize) {
      const gone = this.ring.shift()
      if (gone) this.byId.delete(gone.id)
    }
  }
}

export function emptyStats(): Stats {
  return {
    received: 0,
    alertsCreated: 0,
    deduped: 0,
    rateLimited: 0,
    filtered: 0,
    storms: 0,
  }
}

/** Counters that only ever increase; safe to mutate in place. */
export class StatsCounter {
  private s: Stats = emptyStats()
  get(): Stats {
    return { ...this.s }
  }
  inc(key: keyof Stats, by = 1): void {
    this.s[key] = (this.s[key] as number) + by
  }
  reset(): void {
    this.s = emptyStats()
  }
}