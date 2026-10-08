// dsh-syslog-alert — one ordinary DSH session per calendar day, analysed live.
//
// The host's own `sessionController` hands out ordinary sessions, so the result
// is a normal session in the operator's list: no subagent provider to register,
// and nothing for the plugin to tear down — the host owns the session and
// persists it. The plugin only decides WHERE it is created (an optional absolute
// workspace) and WHAT each message says.
//
// Shape of a day: the first alert creates the session and names it, every later
// alert is admitted as one more prompt into that same session. One session per
// day, one message per alert.
//
// This module never throws at the caller. A drop is reported through `status()`
// and the log, because a syslog pipeline that dies on a host-service hiccup is
// worse than a missed conversation.

import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Alert } from './types.ts'
import { FENCE_CLOSE, FENCE_OPEN, dateKey, sanitizeFences } from './prompt-kit.ts'

/** The instruction line that opens every posted message. */
export const AUTO_SESSION_PROMPT = '分析这条日志'

/** Fallback title prefix; settings normally carry the configured one. */
export const AUTO_SESSION_TITLE_PREFIX = '告警分析'

export const AUTO_SESSION_STATE_FILE = 'auto-session.json'

/** `告警分析 2026-10-07` — prefix plus the LOCAL calendar day. */
export function autoSessionTitle(prefix: string, key: string): string {
  const trimmed = String(prefix ?? '').trim() || AUTO_SESSION_TITLE_PREFIX
  return `${trimmed} ${key}`
}

/**
 * The per-alert prompt: the operator's instruction, the alert's identity, then
 * the raw syslog.
 *
 * Only the instruction line is customisable. The identity lines are not
 * decoration: the session agent has `syslog_alerts` and `syslog_alert_detail`,
 * and without the id it can only grep by guesswork; with it, "分析这条日志"
 * resolves to one exact record. The raw text is fenced and labelled, because a
 * device can put anything in a syslog message — including a line that closes
 * the block and starts impersonating the operator. Letting an operator's custom
 * instruction replace those would let a mistyped prompt silently delete the only
 * context the agent needs.
 *
 * `{id}` and `{device}` expand in the instruction so a per-alert prompt stays
 * possible ("查 {device} 上 {id} 的上下文").
 */
export function buildLogPrompt(alert: Alert, instruction?: string): string {
  const raw = alert.message.raw || alert.message.message || '(空)'
  const device = alert.deviceName ?? '未映射'
  const line = renderInstruction(instruction, alert)
  const head = [
    line,
    '',
    `- 告警 id：${alert.id}`,
    `- 设备：${device}${alert.deviceId ? `（${alert.deviceId}）` : ''}`,
  ].join('\n')
  const trailer = [
    '',
    `分析完成后，请调用工具 syslog_conclude 把结论写回这条告警：参数 alertId=${alert.id}，`,
    'conclusion 为你的完整分析结论（可多行）。不调用该工具，结论就不会进入智能告警中心。',
  ].join('\n')
  return `${head}\n\n${FENCE_OPEN}\n${sanitizeFences(raw)}\n${FENCE_CLOSE}${trailer}\n`
}

/**
 * Substitute the two placeholders an operator may use, falling back to the
 * built-in instruction when the setting is blank.
 */
function renderInstruction(instruction: string | undefined, alert: Alert): string {
  const trimmed = String(instruction ?? '').trim()
  if (!trimmed) return AUTO_SESSION_PROMPT
  return trimmed.replace(/\{id\}/g, alert.id).replace(/\{device\}/g, alert.deviceName ?? alert.deviceId ?? '未映射')
}

// ---- host service surface ----------------------------------------------------

/**
 * The slice of the host `sessionController` service this module uses.
 *
 * Structural on purpose: the plugin must not import `@deepseek-ai/*`, so the
 * shapes below are the contract as documented by the host's own Inspect
 * provider, not a compile-time dependency on it.
 */
export interface SessionControllerLike {
  /** "Create or idempotently adopt one ordinary Session". */
  create(request: { workspaceId?: string; cwd?: string; sessionId?: string; agentPreset?: string }): Promise<{ sessionId?: string }>
  rename(request: { sessionId: string; title: string }): Promise<{ title?: string }>
  /**
   * "Admit one prompt after explicitly resuming its Session".
   *
   * `signal` is REQUIRED by the host, not optional: the implementation opens
   * with `signal.throwIfAborted()`, so handing it `undefined` fails every call
   * with `Cannot read properties of undefined (reading 'throwIfAborted')`.
   * Callers still pass an optional signal; this module always supplies a real
   * one, and only forwards the caller's when it has one.
   */
  prompt(
    request: {
      requestId: string
      sessionId: string
      mode: 'queue' | 'steer'
      content: readonly { type: 'text'; text: string }[]
      clientTimeZone?: string
    },
    signal: AbortSignal,
  ): Promise<unknown>
}

export interface AutoSessionDeps {
  get sessionController(): SessionControllerLike | undefined
  enabled: () => boolean
  titlePrefix: () => string
  /** The operator's own instruction line; blank falls back to the built-in. */
  instruction: () => string
  /**
   * Absolute workspace directory the day's session is created in; blank means
   * "whatever the host's current workspace is".
   *
   * The host rejects a relative `cwd`, so a half-typed path must not reach it:
   * `resolveWorkspace()` returns undefined unless the value is absolute, and the
   * session then falls back to the host default instead of failing the day.
   */
  workspacePath: () => string
  dataDir: () => string
  log: (level: 'warn' | 'info', message: string) => void
  /**
   * Optional back-channel from the auto-session to the alert store: marks the
   * alert as awaiting its day-session conclusion (and records which session it
   * landed in). Called best-effort; absence just means no pending spinner.
   */
  annotate?: (alertId: string, changes: { sessionId?: string; conclusion?: string }) => void
}

export interface AutoSessionStatus {
  enabled: boolean
  reason?: string
  dateKey?: string
  sessionId?: string
  createdAt?: number
  postedToday?: number
  /** True while the day's session came from the state file rather than a create. */
  adopted?: boolean
  /** The absolute workspace the day's session lives in, if one was requested. */
  workspace?: string
}

export interface AutoSessionResult {
  ok: boolean
  sessionId?: string
  dateKey?: string
  error?: string
}

interface DayState {
  dateKey: string
  sessionId: string
  createdAt: number
  posted: number
  adopted: boolean
  /** Absolute workspace this session was created in; undefined = host default. */
  workspace?: string
}

interface PersistedState {
  dateKey?: string
  sessionId?: string
  createdAt?: number
  posted?: number
  workspace?: string
}

/**
 * An absolute path or nothing.
 *
 * `sessionController.create` takes `cwd` and rejects a relative one with an
 * error nobody can act on ("cwd must be absolute"). Operators type paths by
 * hand, so "C:/logs" typed as "logs" or a path pasted with a trailing quote is a
 * normal mistake — treating those as "no workspace" keeps the day's session
 * alive in the host's default workspace instead of losing every alert.
 */
function resolveWorkspace(raw: string | undefined): string | undefined {
  const value = String(raw ?? '').trim()
  if (!value) return undefined
  return /^(?:[A-Za-z]:[\\/]|\/)/.test(value) ? value : undefined
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Owns at most one live conversation. Constructing it is free — no host call
 * happens until the first alert of the day needs a session.
 */
export class AutoSessionRunner {
  private readonly deps: AutoSessionDeps
  private current?: DayState
  private lastError?: string
  /** Serialises session creation, so a syslog storm cannot open two for one day. */
  private creation: Promise<DayState | undefined> = Promise.resolve(undefined)
  private disk?: PersistedState

  constructor(deps: AutoSessionDeps) {
    this.deps = deps
  }

  status(): AutoSessionStatus {
    if (!this.deps.enabled()) return { enabled: false, reason: '当日会话未启用', postedToday: 0 }
    if (!this.deps.sessionController) {
      return { enabled: false, reason: '宿主未提供 sessionController 服务', postedToday: this.current?.posted ?? 0 }
    }
    const base: AutoSessionStatus = this.current
      ? {
          enabled: true,
          dateKey: this.current.dateKey,
          sessionId: this.current.sessionId,
          createdAt: this.current.createdAt,
          postedToday: this.current.posted,
          adopted: this.current.adopted,
          workspace: this.current.workspace,
        }
      : { enabled: true, postedToday: 0 }
    // A failure after the session exists is still the operator's news: without
    // this the panel would show a healthy day whose alerts silently stopped
    // landing, because the drop is only visible in the log otherwise.
    if (this.lastError) return { ...base, reason: this.lastError }
    if (!this.current) return { ...base, reason: '今日会话尚未创建（等待第一条日志）' }
    return base
  }

  /**
   * Admit one alert as a prompt in its date's session. Never rejects.
   *
   * Deliveries are serialised per day through a single-chain tail. Sharing one
   * `Promise` field by read-modify-write is the known trap here: two concurrent
   * callers would both chain onto the same already-settled promise and create
   * two sessions for one morning — which is exactly what a syslog storm does.
   */
  async post(alert: Alert, signal?: AbortSignal): Promise<AutoSessionResult> {
    const key = dateKey(alert.receivedAt)
    // The caller gates on the setting too; checking here as well keeps the
    // module honest on its own — a disabled feature must not quietly open a
    // conversation just because someone called post() directly.
    if (!this.deps.enabled()) return { ok: false, error: '当日会话未启用', dateKey: key }
    try {
      const created = this.creation.then(
        () => this.ensure(key),
        () => this.ensure(key),
      )
      this.creation = created.then(
        () => undefined,
        () => undefined,
      )
      const day = await created
      if (!day) return { ok: false, error: this.lastError ?? '当日会话不可用', dateKey: key }

      // Increment the day the prompt actually landed in: a stale adopted id
      // makes deliver() swap in a fresh session, and counting on the discarded
      // object would persist a total one short of reality.
      const used = await this.deliver(day, buildLogPrompt(alert, this.deps.instruction()), signal)
      used.posted += 1
      this.persist()
      this.lastError = undefined
      this.deps.log('info', `告警 ${alert.id} 已投递到当日会话「${autoSessionTitle(this.deps.titlePrefix(), key)}」（${used.sessionId}）`)
      // Mark the alert as awaiting its conclusion. The agent turn is async; the
      // conclusion lands later through syslog_conclude, which patches the alert
      // and clears analysisPending. If the host has no way to write back, we
      // leave it false rather than spinning forever on nothing.
      try {
        this.deps.annotate?.(alert.id, { sessionId: used.sessionId, conclusion: undefined })
      } catch {
        /* annotate is best-effort */
      }
      return { ok: true, sessionId: used.sessionId, dateKey: key }
    } catch (err) {
      this.lastError = message(err)
      this.deps.log('warn', `投递到当日会话失败：${this.lastError}`)
      return { ok: false, error: this.lastError, dateKey: key }
    }
  }

  /** Drops the in-memory reference only. The host owns the session, not us. */
  dispose(): void {
    this.current = undefined
  }

  /** Admits the prompt, returning the day it landed in (deliver may re-create). */
  private async deliver(day: DayState, prompt: string, signal?: AbortSignal): Promise<DayState> {
    const svc = this.deps.sessionController
    if (!svc || typeof svc.prompt !== 'function') throw new Error('宿主未提供 sessionController.prompt')
    try {
      await this.admit(svc, day.sessionId, prompt, signal)
      return day
    } catch (err) {
      // An adopted id can be stale: the operator deleted the session, or the
      // host rewrote its store. Reusing it forever would drop every alert from
      // this day with an error nobody reads, so fall back to a fresh session
      // once rather than giving up.
      if (!day.adopted) throw err
      this.deps.log('warn', `沿用的当日会话 ${day.sessionId} 不可用（${message(err)}），改新建一个`)
      const fresh = await this.create(day.dateKey, day)
      await this.admit(svc, fresh.sessionId, prompt, signal)
      return fresh
    }
  }

  private admit(svc: SessionControllerLike, sessionId: string, prompt: string, signal?: AbortSignal): Promise<unknown> {
    // Never hand the host `undefined` here: its prompt() dereferences the signal
    // immediately. A fire-and-forget delivery has no caller signal, so it gets a
    // live one that simply never aborts.
    const abortable = signal ?? new AbortController().signal
    return svc.prompt(
      {
        // A per-admission id: the host uses it for idempotency, so reusing one
        // would collapse two alerts into a single turn.
        requestId: randomUUID(),
        sessionId,
        mode: 'queue',
        content: [{ type: 'text', text: prompt }],
      },
      abortable,
    )
  }

  /** Returns the day's session, creating (or adopting) it at most once. */
  private async ensure(key: string): Promise<DayState | undefined> {
    if (this.current && this.current.dateKey === key) return this.current
    const svc = this.deps.sessionController
    if (!svc || typeof svc.create !== 'function') {
      this.lastError = '宿主未提供 sessionController 服务'
      return undefined
    }

    const persisted = this.loadState()
    if (persisted?.sessionId && persisted.dateKey === key) {
      // A plugin reload mid-day must not open a second conversation for the
      // same date; the host persisted the first one, so keep using it.
      const day: DayState = {
        dateKey: key,
        sessionId: String(persisted.sessionId),
        createdAt: Number.isFinite(persisted.createdAt) ? Number(persisted.createdAt) : Date.now(),
        posted: Number.isFinite(persisted.posted) ? Number(persisted.posted) : 0,
        adopted: true,
        // Report the workspace the session was ACTUALLY created in, not the one
        // the setting holds now: after a reload with a changed setting, the
        // panel must not claim a location the live session does not have.
        workspace: resolveWorkspace(persisted.workspace),
      }
      this.current = day
      return day
    }
    return this.create(key)
  }

  private async create(key: string, previous?: DayState): Promise<DayState> {
    const svc = this.deps.sessionController
    if (!svc || typeof svc.create !== 'function') throw new Error('宿主未提供 sessionController.create')
    const requested = String(this.deps.workspacePath?.() ?? '').trim()
    const workspace = resolveWorkspace(requested)
    if (requested && !workspace) {
      // One warning, then carry on with the host default: losing the whole day
      // over a malformed path would be a far worse answer than a session in the
      // wrong place, and the log says exactly which value was rejected.
      this.deps.log('warn', `告警会话工作区「${requested}」不是绝对路径，已改用宿主默认工作区`)
    }
    const created = workspace ? await svc.create({ cwd: workspace }) : await svc.create({})
    const sessionId = String(created?.sessionId ?? '')
    if (!sessionId) throw new Error('sessionController.create 未返回 sessionId')
    const title = autoSessionTitle(this.deps.titlePrefix(), key)
    try {
      await svc.rename({ sessionId, title })
    } catch (err) {
      // The title is cosmetic next to the analysis itself; a host that refuses
      // the rename must not cost the operator the whole day's conversation.
      this.deps.log('warn', `当日会话标题设置失败（${message(err)}），会话 ${sessionId} 仍会继续投递`)
    }
    const day: DayState = { dateKey: key, sessionId, createdAt: Date.now(), posted: previous?.posted ?? 0, adopted: false, workspace }
    this.current = day
    this.persist()
    this.deps.log('info', `已创建当日告警会话「${title}」（${sessionId}）${workspace ? ` · 工作区 ${workspace}` : ''}`)
    return day
  }

  private statePath(): string {
    return join(this.deps.dataDir(), AUTO_SESSION_STATE_FILE)
  }

  private loadState(): PersistedState | undefined {
    if (this.disk !== undefined) return this.disk
    try {
      this.disk = JSON.parse(readFileSync(this.statePath(), 'utf-8')) as PersistedState
    } catch {
      // Missing or malformed state only means "start a fresh day".
      this.disk = undefined
    }
    return this.disk
  }

  private persist(): void {
    const day = this.current
    if (!day) return
    const state: PersistedState = {
      dateKey: day.dateKey,
      sessionId: day.sessionId,
      createdAt: day.createdAt,
      posted: day.posted,
      workspace: day.workspace,
    }
    this.disk = state
    try {
      mkdirSync(this.deps.dataDir(), { recursive: true })
      writeFileSync(this.statePath(), JSON.stringify(state, null, 2), 'utf-8')
    } catch {
      // Losing the pointer costs one extra session after a reload, nothing more.
    }
  }
}
