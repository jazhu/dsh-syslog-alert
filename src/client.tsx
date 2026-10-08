/**
 * dsh-syslog-alert — client half (browser bundle).
 *
 * Registers a right-sidebar tab 「智能告警中心」 and renders the alert stream:
 * a live list with a severity strip, filter bar and a received-at column; the
 * detail (raw syslog, parse confidence, the day-session agent's conclusion) is
 * a modal opened from a row.
 *
 * A settings sheet exposes the knobs that change behaviour at runtime (ports,
 * severity floor, dedup/rate/storm, day session). The host ignores host-owned
 * fields, so the form sends only the editable subset.
 *
 * All data goes through the host's loopback `/syslog-api` on a fixed port; the
 * token is bootstrapped from GET /_session on the same origin. Live updates
 * arrive over SSE rather than polling.
 *
 * Styling is a single injected <style> block using only the host's
 * --dsw-alias-* / --dsw-radius-* theme tokens, so the panel follows the app's
 * light/dark palettes. No @deepseek-ai/dsh-client-ui-primitives import: the
 * harness does not expose it to client bundles, and hand-built controls are
 * what the sibling plugin does too.
 */
import { createElement as h, useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactElement } from 'react'
import type { Alert, EditableSettings, ListenerStatus, Stats, SyslogMessage } from './types.ts'

const PANEL_ID = 'dsh-syslog-alert'
const API_PORT = 18784
const API = `http://127.0.0.1:${API_PORT}/syslog-api`
const TOKEN_KEY = 'dsh-syslog-alert-token'

const SEVERITY_LABELS = ['紧急', '严重', '严重', '错误', '警告', '通知', '信息', '调试']

// Mirrors AUTO_SESSION_PROMPT in auto-session.ts, deliberately NOT imported:
// that module reaches for node:fs and node:crypto, which the browser bundle does
// not have. The gate below asserts the two stay equal in meaning.
const AUTO_SESSION_PROMPT = '分析这条日志'

/**
 * Whether a workspace value is one the host will accept as `cwd`.
 *
 * Kept as a literal rather than node:path so the browser bundle stays
 * dependency-free; `resolveWorkspace` in auto-session.ts applies the same rule.
 */
function isAbsolutePath(value: string | undefined): boolean {
  return /^(?:[A-Za-z]:[\\/]|\/)/.test(String(value ?? '').trim())
}
const STAGE_LABELS: Record<string, string> = {
  received: '已接收',
  mapped: '已映射',
  filtered: '仅留存',
  deduped: '去重/风暴',
  closed: '已关闭',
  failed: '失败',
}

// ---- styling -----------------------------------------------------------------

let cssInjected = false
function injectStyles(): void {
  if (cssInjected || typeof document === 'undefined') return
  cssInjected = true
  const el = document.createElement('style')
  el.setAttribute('data-syslog-alert', '')
  el.textContent = CSS
  document.head.appendChild(el)
}

// ---- token / api -------------------------------------------------------------

let sessionToken: string | null = null
let tokenProbed = false
let manualToken: string | null = null
type TokenNotice = (reason: string) => void
let tokenNotice: TokenNotice | null = null

async function bootstrapToken(): Promise<string> {
  if (tokenProbed) return manualToken ?? sessionToken ?? ''
  tokenProbed = true
  let stored: string | null = null
  try {
    stored = localStorage.getItem(TOKEN_KEY)
  } catch {
    /* private mode */
  }
  if (stored) {
    manualToken = stored
    return stored
  }
  try {
    const r = await fetch(API + '/_session')
    const j = (await r.json()) as { token?: string; enabled?: boolean }
    if (j.enabled && j.token) sessionToken = j.token
  } catch {
    /* host not up yet; the panel will show the error on its first real call */
  }
  return manualToken ?? sessionToken ?? ''
}

async function api<T>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const token = await bootstrapToken()
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (token) headers['X-Syslog-Token'] = token
  const res = await fetch(API + path, {
    method: opts.method ?? 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })
  if (res.status === 401) {
    // Same wording as the sibling plugin: the host does exempt its own webview,
    // so this message must not imply a loopback origin is the problem.
    const reason = '智能告警中心访问令牌缺失或无效。host 已放行本机来源；若仍报错，请粘贴本机令牌后重试。'
    tokenNotice?.(reason)
    throw new Error(reason)
  }
  const j = (await res.json()) as T & { ok?: boolean; error?: { message?: string } }
  if (j.ok === false && j.error) throw new Error(j.error.message ?? 'request failed')
  return j
}

// ---- shared state ------------------------------------------------------------

interface Filters {
  severityMax: number
  deviceId: string
  stage: string
  search: string
  sinceMinutes: number
}

const DEFAULT_FILTERS: Filters = { severityMax: 7, deviceId: '', stage: '', search: '', sinceMinutes: 0 }

/** Merge an SSE payload into the cached list without refetching the page. */
function mergeAlert(list: Alert[], incoming: Alert): Alert[] {
  const idx = list.findIndex((a) => a.id === incoming.id)
  if (idx < 0) return [incoming, ...list]
  const next = list.slice()
  next[idx] = incoming
  return next
}

// ---- pieces ------------------------------------------------------------------

function sevClass(sev: number): string {
  if (sev <= 2) return 's0'
  if (sev === 3) return 's3'
  if (sev === 4) return 's4'
  return 's5'
}

/**
 * Day and clock of one timestamp, formatted by hand rather than through
 * `toLocaleString`: the list column needs a fixed-width, tabular shape so two
 * rows line up, and a locale string changes width and separators per machine.
 */
function fmtDay(at: number): string {
  const d = new Date(at)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

function fmtClock(at: number): string {
  const d = new Date(at)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

/**
 * Column header for the list.
 *
 * The received-at column is easy to misread as "when the device emitted this",
 * so it is labelled at the top instead of only inside each row.
 */
function AlertListHead(): ReactElement {
  return h('div', { className: 'sla-row head' },
    h('span', { className: 'sla-sev' }),
    h('div', { className: 'sla-main' }, '设备 / 摘要'),
    h('div', { className: 'sla-col-time' }, '接收时间'),
  )
}

function AlertRow(props: { alert: Alert; selected: boolean; onSelect: () => void }): ReactElement {
  const { alert, selected, onSelect } = props
  const sev = alert.message.severity ?? 7
  const excerpt = alert.message.message.replace(/\s+/g, ' ').slice(0, 160)
  return h('button', { className: `sla-row${selected ? ' on' : ''}`, onClick: onSelect },
    h('span', { className: `sla-sev ${sevClass(sev)}` }),
    h('div', { className: 'sla-main' },
      h('div', { className: 'sla-line1' },
        h('b', null, alert.deviceName ?? '未映射设备'),
        alert.message.tag ? h('code', null, alert.message.tag) : null,
        alert.count > 1 ? h('span', { className: 'sla-rep' }, `×${alert.count}`) : null,
      ),
      h('div', { className: 'sla-line2' }, excerpt),
      h('div', { className: 'sla-line3' },
        h('span', { className: 'sla-badge' }, STAGE_LABELS[alert.stage] ?? alert.stage),
        alert.sessionConclusion || alert.analysisPending
          ? h('span', { className: `sla-badge v${alert.analysisPending ? ' warn' : ''}` }, alert.analysisPending ? '分析中' : '有结论')
          : null,
      ),
    ),
    h('div', { className: 'sla-col-time' },
      h('span', { className: 'sla-t-d' }, fmtDay(alert.receivedAt)),
      h('span', { className: 'sla-t-t' }, fmtClock(alert.receivedAt)),
    ),
  )
}

function Block(props: { title: string; tone?: 'ok' | 'err' | 'warn'; children?: ReactElement | ReactElement[] | null }): ReactElement {
  return h('section', { className: `sla-block${props.tone ? ' ' + props.tone : ''}` },
    h('h4', { className: 'sla-block-t' }, props.title),
    props.children,
  )
}

function AlertDetail(props: { alert: Alert; onAck: () => void }): ReactElement {
  const { alert, onAck } = props
  const m: SyslogMessage = alert.message
  return h('div', { className: 'sla-detail' },
    h('div', { className: 'sla-dhead' },
      h('div', null,
        h('div', { className: 'sla-dtitle' },
          h('span', { className: `sla-sev ${sevClass(m.severity ?? 7)}`, style: { height: 14, borderRadius: 3 } }),
          alert.deviceName ?? '未映射设备',
          m.tag ? h('code', null, m.tag) : null,
        ),
        h('div', { className: 'sla-dmeta' },
          `${new Date(alert.receivedAt).toLocaleString('zh-CN', { hour12: false })}`,
          ` · 来源 ${alert.sourceIp ?? '?'}`,
          ` · ${alert.transport?.toUpperCase() ?? '?'}`,
          ` · 级别 ${m.severityName ?? SEVERITY_LABELS[m.severity ?? 7] ?? '?'}`,
          ` · 解析可信度 ${m.confidence}`,
          alert.count > 1 ? ` · 重复 ${alert.count} 次` : '',
        ),
      ),
      h('div', { className: 'sla-dacts' },
        alert.ackedAt ? h('span', { className: 'sla-badge' }, '已确认') : h('button', { className: 'sla-btn plain', onClick: onAck }, '确认'),
      ),
    ),

    m.confidence === 'raw'
      ? h('div', { className: 'sla-warn-box' }, '这条日志无法识别为 RFC3164/5424，结构化字段不可信。原始文本见下。')
      : null,
    alert.dropReason ? h('div', { className: 'sla-warn-box' }, `未进入分析：${alert.dropDetail ?? alert.dropReason}`) : null,

    h(Block, { key: 'raw', title: '原始 syslog', children: h('pre', { className: 'sla-pre' }, m.raw) }),

    alert.sessionConclusion || alert.analysisPending
      ? h(Block, { key: 'session', title: alert.analysisPending ? '会话分析中' : '会话分析结论', tone: alert.analysisPending ? 'warn' : 'ok',
          children: h('div', null,
            alert.sessionConclusion
              ? h('p', { className: 'sla-p' }, alert.sessionConclusion)
              : h('p', { className: 'sla-p sub' }, '已投递到当日会话，等待 agent 分析并调用 syslog_conclude 写回…'),
            h('p', { className: 'sla-p sub' },
              alert.sessionId ? `会话 ${alert.sessionId.slice(0, 8)}` : '',
              alert.sessionConclusionAt ? ` · 提取于 ${new Date(alert.sessionConclusionAt).toLocaleString('zh-CN', { hour12: false })}` : '',
            ),
          ),
        })
      : null,

    h(Block, { key: 'timeline', title: '处理时间线',
      children: h('div', { className: 'sla-tl' },
        alert.timeline.map((t, i) =>
          h('div', { key: i, className: 'sla-tl-row' },
            h('span', { className: 'sla-tl-t' }, new Date(t.at).toLocaleTimeString('zh-CN', { hour12: false })),
            h('span', { className: 'sla-tl-s' }, STAGE_LABELS[t.stage] ?? t.stage),
            h('span', { className: 'sla-tl-n' }, t.note),
            t.durationMs !== undefined ? h('span', { className: 'sla-tl-d' }, `${t.durationMs}ms`) : null,
          ),
        ),
      ),
    }),
  )
}

/**
 * The detail view in a modal.
 *
 * The same body as the old right-hand pane, wrapped in the settings sheet's
 * scrim so one alert can be read at full width without the list being squeezed
 * to half the panel. Escape closes it, which is the only keyboard affordance a
 * modal needs here — there is no form to submit.
 */
function AlertModal(props: { alert: Alert; onAck: () => void; onClose: () => void }): ReactElement {
  const { alert, onAck, onClose } = props
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return h('div', { className: 'sla-scrim', onClick: (e: any) => { if (e.target === e.currentTarget) onClose() } },
    h('div', { className: 'sla-modal sla-modal-wide', onClick: (e: any) => e.stopPropagation() },
      h('div', { className: 'sla-modal-head' },
        h('b', null, `${alert.deviceName ?? '未映射设备'}${alert.message.tag ? ' · ' + alert.message.tag : ''}`),
        h('button', { className: 'sla-x', onClick: onClose }, '×'),
      ),
      h('div', { className: 'sla-modal-body' },
        h(AlertDetail, { alert, onAck }),
      ),
      h('div', { className: 'sla-modal-foot' },
        h('button', { className: 'sla-btn', onClick: onClose }, '关闭'),
      ),
    ),
  )
}

// ---- settings ----------------------------------------------------------------

function Settings(props: { settings: EditableSettings; onSave: (s: EditableSettings) => Promise<void>; onClose: () => void }): ReactElement {
  const [draft, setDraft] = useState<EditableSettings>(props.settings)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const set = <K extends keyof EditableSettings>(k: K, v: EditableSettings[K]): void => setDraft((d) => ({ ...d, [k]: v }))
  const num = (k: keyof EditableSettings, v: string): void =>
    setDraft((d) => ({ ...d, [k]: v === '' ? undefined : Math.max(0, Number(v)) }))

  const save = async (): Promise<void> => {
    setBusy(true)
    setErr(null)
    try {
      await props.onSave(draft)
      props.onClose()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return h('div', { className: 'sla-scrim', onClick: (e: any) => { if (e.target === e.currentTarget) props.onClose() } },
    h('div', { className: 'sla-modal' },
      h('div', { className: 'sla-modal-head' },
        h('b', null, '智能告警中心设置'),
        h('button', { className: 'sla-x', onClick: props.onClose }, '×'),
      ),
      h('div', { className: 'sla-modal-body' },
        err ? h('div', { className: 'sla-msg err' }, err) : null,
        h('div', { className: 'sla-note' },
          '端口与传输改动会重启监听（会短暂中断收包）。apiPort / dataDir 由宿主管理，此处不可改。',
        ),

        h('div', { className: 'sla-field' },
          h('label', null, '监听端口', h('i', null, '逗号分隔；Linux 下 514 需提权，绑不上会显示原因')),
          h('input', { className: 'sla-input', value: (draft.syslogPorts ?? []).join(','), onChange: (e: any) => set('syslogPorts', String(e.target.value ?? '').split(',').map((x: string) => Number(x.trim())).filter((n: number) => Number.isFinite(n) && n > 0)) }),
        ),
        h('div', { className: 'sla-field' },
          h('label', null, '同时启用 TCP 接收'),
          h('input', { type: 'checkbox', className: 'sla-cb', checked: draft.enableTcp === true, onChange: (e: any) => set('enableTcp', e.target.checked) }),
        ),
        h('div', { className: 'sla-field' },
          h('label', null, '未映射来源策略'),
          h('select', { className: 'sla-input', value: draft.unmappedPolicy ?? 'ignore', onChange: (e: any) => set('unmappedPolicy', e.target.value as never) },
            h('option', { value: 'ignore' }, '忽略丢弃'),
            h('option', { value: 'capture-only' }, '收下标红但绝不分析'),
          ),
        ),
        h('div', { className: 'sla-field' },
          h('label', null, 'hillstone 运维 API 端口', h('i', null, '留 0 = 自动探测。设备列表与 SSH 采集都走它')),
          h('input', { className: 'sla-input', type: 'number', min: 0, max: 65535, value: draft.opsApiPort ?? 0, onChange: (e: any) => num('opsApiPort', e.target.value) }),
        ),
        h('div', { className: 'sla-field' },
          h('label', null, '最低级别', h('i', null, '0=emerg 最严重；高于该值直接丢弃')),
          h('input', { className: 'sla-input', type: 'number', min: 0, max: 7, value: draft.minSeverity ?? 5, onChange: (e: any) => num('minSeverity', e.target.value) }),
        ),
        h('div', { className: 'sla-field' },
          h('label', null, 'mnemonic 白名单', h('i', null, '逗号分隔；留空 = 不限')),
          h('input', { className: 'sla-input', value: (draft.mnemonicAllow ?? []).join(','), onChange: (e: any) => set('mnemonicAllow', String(e.target.value ?? '').split(',').map((x: string) => x.trim()).filter(Boolean)) }),
        ),
        h('div', { className: 'sla-grid2' },
          h('div', { className: 'sla-field' },
            h('label', null, '去重窗口（秒）'),
            h('input', { className: 'sla-input', type: 'number', min: 0, value: draft.dedupWindowSec ?? 120, onChange: (e: any) => num('dedupWindowSec', e.target.value) }),
          ),
          h('div', { className: 'sla-field' },
            h('label', null, '每设备每分钟上限'),
            h('input', { className: 'sla-input', type: 'number', min: 0, value: draft.perDeviceRatePerMin ?? 20, onChange: (e: any) => num('perDeviceRatePerMin', e.target.value) }),
          ),
          h('div', { className: 'sla-field' },
            h('label', null, '风暴阈值', h('i', null, '窗口内重复达此数即聚合成一条')),
            h('input', { className: 'sla-input', type: 'number', min: 0, value: draft.stormThreshold ?? 5, onChange: (e: any) => num('stormThreshold', e.target.value) }),
          ),
          h('div', { className: 'sla-field' },
            h('label', null, '保留天数'),
            h('input', { className: 'sla-input', type: 'number', min: 1, value: draft.retentionDays ?? 14, onChange: (e: any) => num('retentionDays', e.target.value) }),
          ),
        ),
        h('div', { className: 'sla-grid2' },
          h('div', { className: 'sla-field row' },
            h('label', null, '启用 agent 在线分析', h('i', null, '当天第一条日志新建普通会话，后续日志接着投递；无需 provider')),
            h('input', { type: 'checkbox', className: 'sla-cb', checked: draft.autoSessionEnabled !== false, onChange: (e: any) => set('autoSessionEnabled', e.target.checked) }),
          ),
        ),
        draft.autoSessionEnabled !== false
          ? h('div', { className: 'sla-field' },
              h('label', null, '当日会话标题前缀', h('i', null, '会话标题为「前缀 + 本地日期」；留空则用 告警分析')),
              h('input', { className: 'sla-input', value: draft.autoSessionTitle ?? '', onChange: (e: any) => set('autoSessionTitle', String(e.target.value ?? '')), placeholder: '告警分析' }),
            )
          : null,
        draft.autoSessionEnabled !== false
          ? h('div', { className: 'sla-field' },
              h('label', null, '当日会话工作区', h('i', null, '会话创建所在的绝对路径；留空 = 用宿主当前工作区')),
              h('input', { className: 'sla-input', value: draft.autoSessionWorkspace ?? '', onChange: (e: any) => set('autoSessionWorkspace', String(e.target.value ?? '')), placeholder: 'D:\\workspace\\dsh_plugin' }),
              // Warn while typing rather than after saving: the host rejects a
              // relative `cwd`, and the fallback is silently "host default", so
              // an operator who typed `logs` must be told it will not be used.
              String(draft.autoSessionWorkspace ?? '').trim() && !isAbsolutePath(draft.autoSessionWorkspace)
                ? h('div', { className: 'sla-note' }, `「${String(draft.autoSessionWorkspace).trim()}」不是绝对路径，保存后会改用宿主当前工作区`)
                : null,
            )
          : null,
        draft.autoSessionEnabled !== false
          ? h('div', { className: 'sla-field' },
              h('label', null, '创建会话提示词', h('i', null, '只替换首行指令；告警 id、设备名与原始日志由插件追加。可用 {id} 与 {device}')),
              h('textarea', {
                className: 'sla-input sla-textarea',
                rows: 3,
                value: draft.autoSessionPrompt ?? '',
                onChange: (e: any) => set('autoSessionPrompt', String(e.target.value ?? '')),
                placeholder: '分析这条日志',
              }),
              String(draft.autoSessionPrompt ?? '').trim() === ''
                ? h('div', { className: 'sla-note' }, `留空即使用默认指令「${AUTO_SESSION_PROMPT}」`)
                : null,
            )
          : null,
      ),
      h('div', { className: 'sla-modal-foot' },
        h('button', { className: 'sla-btn primary', disabled: busy, onClick: () => void save() }, busy ? '保存中…' : '保存'),
        h('button', { className: 'sla-btn', onClick: props.onClose }, '取消'),
      ),
    ),
  )
}

// ---- main page ---------------------------------------------------------------

function AlertCenterPage(): ReactElement {
  injectStyles()
  const [tab, setTab] = useState<'alerts' | 'stats' | 'selftest'>('alerts')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<Alert | null>(null)
  const [status, setStatus] = useState<ListenerStatus | null>(null)
  const [stats, setStats] = useState<Stats | null>(null)
  const [devices, setDevices] = useState<{ id: string; name?: string; ip?: string }[]>([])
  const [error, setError] = useState<string | null>(null)
  const [tokenMsg, setTokenMsg] = useState<string | null>(null)
  const [tokenInput, setTokenInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [editable, setEditable] = useState<EditableSettings>({})
  const [testMsg, setTestMsg] = useState<{ message?: string; sourceIp?: string }>({ message: '<13>Oct  7 10:12:33 SW1 LINK-3: Interface GE1/0/1 link status changed to DOWN' })

  useEffect(() => {
    tokenNotice = setTokenMsg
    return () => { tokenNotice = null }
  }, [])

  const query = useMemo(() => {
    const p = new URLSearchParams()
    if (filters.severityMax < 7) p.set('severityMax', String(filters.severityMax))
    if (filters.deviceId) p.set('deviceId', filters.deviceId)
    if (filters.stage) p.set('stage', filters.stage)
    if (filters.search) p.set('q', filters.search)
    if (filters.sinceMinutes > 0) p.set('since', String(filters.sinceMinutes * 60_000))
    p.set('limit', '200')
    return p.toString()
  }, [filters])

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const j = await api<{ alerts: Alert[]; total: number }>(`/alerts?${query}`)
      setAlerts(j.alerts ?? [])
      setTotal(j.total ?? 0)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [query])

  // One poll for the list plus a slower one for listener health: a dead receiver
  // is exactly the state nobody would otherwise notice until an alert is missed.
  useEffect(() => {
    void refresh()
    const t = setInterval(() => void refresh(), 15_000)
    return () => clearInterval(t)
  }, [refresh])

  useEffect(() => {
    const load = async (): Promise<void> => {
      try {
        const j = await api<{ listener: ListenerStatus; stats: Stats; config: EditableSettings; devices: typeof devices }>('/status')
        setStatus(j.listener)
        setStats(j.stats)
        setEditable(j.config)
        setDevices(j.devices ?? [])
      } catch (e) {
        setError((e as Error).message)
      }
    }
    void load()
    const t = setInterval(() => void load(), 10_000)
    return () => clearInterval(t)
  }, [])

  // SSE: a new alert or a stage advance lands without the operator refreshing.
  useEffect(() => {
    let es: EventSource | null = null
    let closed = false
    const connect = async (): Promise<void> => {
      const token = await bootstrapToken()
      // EventSource cannot set headers, so the token travels as a query param on
      // the one route that may be called without it when the origin is local.
      const url = `${API}/alerts/stream?token=${encodeURIComponent(token)}`
      es = new EventSource(url)
      const onMsg = (e: MessageEvent): void => {
        try {
          const data = JSON.parse(e.data) as { alert: Alert }
          if (!data.alert) return
          setAlerts((prev) => mergeAlert(prev, data.alert))
          setSelectedId((cur) => (cur === data.alert.id ? data.alert.id : cur))
        } catch {
          /* ignore */
        }
      }
      es.addEventListener('alert', onMsg as EventListener)
      es.addEventListener('update', onMsg as EventListener)
      es.onerror = () => {
        // EventSource retries on its own; nothing to do but avoid a hot loop if
        // the host is gone (the list poll keeps working as the fallback).
      }
    }
    void connect()
    return () => {
      closed = true
      void closed
      es?.close()
    }
  }, [])

  useEffect(() => {
    if (!selectedId) {
      setDetail(null)
      return
    }
    let live = true
    api<{ alert: Alert }>(`/alerts/${encodeURIComponent(selectedId)}`)
      .then((j) => { if (live) setDetail(j.alert) })
      .catch(() => { if (live) setDetail(null) })
    return () => { live = false }
  }, [selectedId])

  const ack = async (): Promise<void> => {
    if (!selectedId) return
    await api(`/alerts/${encodeURIComponent(selectedId)}/ack`, { method: 'POST' })
    void refresh()
  }

  const saveSettings = async (s: EditableSettings): Promise<void> => {
    await api('/settings', { method: 'PUT', body: s })
    const j = await api<{ listener: ListenerStatus; stats: Stats; config: EditableSettings }>('/status')
    setStatus(j.listener)
    setStats(j.stats)
    setEditable(j.config)
  }

  const injectTest = async (): Promise<void> => {
    await api('/test-alert', { method: 'POST', body: testMsg })
    void refresh()
  }

  /**
   * Start/stop the syslog sockets without unloading the plugin.
   *
   * The 10s status poll would eventually reflect the change on its own, but an
   * operator who just clicked "stop" and still sees "运行中" for ten seconds will
   * click again — so the response is applied immediately.
   */
  const controlListener = async (action: 'start' | 'stop'): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      const j = await api<{ status: ListenerStatus; error?: string | null }>('/listener', { method: 'POST', body: { action } })
      if (j.status) setStatus(j.status)
      if (j.error) setError(j.error)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const s = stats
  return h('div', { className: 'sla-root' },
    h('div', { className: 'sla-seg' },
      h('button', { className: tab === 'alerts' ? 'on' : '', onClick: () => setTab('alerts') }, `告警${total ? ` (${total})` : ''}`),
      h('button', { className: tab === 'selftest' ? 'on' : '', onClick: () => setTab('selftest') }, '自检'),
      h('button', { className: tab === 'stats' ? 'on' : '', onClick: () => setTab('stats') }, '运行状态'),
      h('span', { style: { flex: 1 } }),
      h('button', { className: 'sla-btn plain', onClick: () => setShowSettings(true) }, '设置'),
    ),

    tokenMsg
      ? h('div', { className: 'sla-msg err' },
          h('code', null, tokenMsg),
          h('div', { className: 'sla-acts' },
            h('input', { className: 'sla-input', style: { flex: 1 }, placeholder: '粘贴令牌', value: tokenInput, onChange: (e: any) => setTokenInput(e.target.value) }),
            h('button', { className: 'sla-btn primary', onClick: () => {
              try { localStorage.setItem(TOKEN_KEY, tokenInput.trim()) } catch { /* ignore */ }
              manualToken = tokenInput.trim()
              tokenProbed = false
              setTokenMsg(null)
              location.reload()
            } }, '保存并重试'),
          ),
        )
      : null,

    error ? h('div', { className: 'sla-msg err' }, error) : null,

    tab === 'alerts'
      ? h('div', { className: 'sla-body' },
          h('div', { className: 'sla-pane list' },
            h('div', { className: 'sla-filters' },
              h('input', { className: 'sla-input', placeholder: '搜索日志/标签/设备', value: filters.search, onChange: (e: any) => setFilters((f) => ({ ...f, search: e.target.value })) }),
              h('select', { className: 'sla-input', value: filters.severityMax, onChange: (e: any) => setFilters((f) => ({ ...f, severityMax: Number(e.target.value) })) },
                [7, 6, 5, 4, 3, 2, 1, 0].map((n: number) => h('option', { key: n, value: n }, n === 7 ? '全部级别' : `≤ ${n} ${SEVERITY_LABELS[n] ?? ''}`)),
              ),
              h('select', { className: 'sla-input', value: filters.stage, onChange: (e: any) => setFilters((f) => ({ ...f, stage: e.target.value })) },
                h('option', { value: '' }, '全部阶段'),
                Object.entries(STAGE_LABELS).map(([k, v]) => h('option', { key: k, value: k }, v)),
              ),
              h('select', { className: 'sla-input', value: filters.deviceId, onChange: (e: any) => setFilters((f) => ({ ...f, deviceId: e.target.value })) },
                h('option', { value: '' }, '全部设备'),
                devices.map((d) => h('option', { key: d.id, value: d.id }, d.name ?? d.ip ?? d.id)),
              ),
              h('select', { className: 'sla-input', value: filters.sinceMinutes, onChange: (e: any) => setFilters((f) => ({ ...f, sinceMinutes: Number(e.target.value) })) },
                h('option', { value: 0 }, '全部时间'),
                h('option', { value: 15 }, '近 15 分钟'),
                h('option', { value: 60 }, '近 1 小时'),
                h('option', { value: 1440 }, '近 24 小时'),
              ),
            ),
            h(AlertListHead),
            h('div', { className: 'sla-rows' },
              alerts.length === 0
                ? h('div', { className: 'sla-empty' },
                    h('b', null, '没有告警'),
                    h('div', { style: { marginTop: 4 } },
                      status?.listening
                        ? `监听运行中，已收 ${status.packets} 个包。去「自检」页注入一条测试日志验证链路。`
                        : '监听未运行，去「运行状态」页看绑定失败原因。'),
                  )
                : alerts.map((a) => h(AlertRow, { key: a.id, alert: a, selected: a.id === selectedId, onSelect: () => setSelectedId(a.id) })),
            ),
          ),
        )
      : tab === 'selftest'
      ? h('div', { className: 'sla-body' },
          h('div', { className: 'sla-pane single' },
            h('div', { className: 'sla-test' },
              h('div', { className: 'sla-note' }, '把下面这条当作从设备发来的报文注入，走完整链路（解析→映射→预过滤→分析→当日会话）。注入后回「告警」页看它。'),
              h('div', { className: 'sla-test-row' },
                h('input', { className: 'sla-input', value: testMsg.message ?? '', onChange: (e: any) => setTestMsg((t) => ({ ...t, message: e.target.value })) }),
                h('input', { className: 'sla-input', style: { width: 130 }, placeholder: '来源 IP', value: testMsg.sourceIp ?? '', onChange: (e: any) => setTestMsg((t) => ({ ...t, sourceIp: e.target.value })) }),
                h('button', { className: 'sla-btn primary', onClick: () => void injectTest() }, '注入'),
              ),
            ),
            status
              ? h('div', { className: `sla-msg ${status.listening ? 'ok' : 'err'}` },
                  status.listening
                    ? `监听运行中 · ${status.transports.join(' + ') || '?'} · 端口 ${status.boundPorts.join(', ') || '无'} · 已收 ${status.packets} 包`
                    : '监听未运行：自检注入不依赖收包端口，但真实设备日志进不来。')
              : null,
            h('div', { className: 'sla-note' }, '来源 IP 留空时用本机回环地址，因此能否命中设备映射取决于有没有把 127.0.0.1 配进设备列表。'),
          ),
        )
      : h('div', { className: 'sla-body' },
          h('div', { className: 'sla-pane single' },
            status
                  ? h('div', null,
                      h('div', { className: `sla-msg ${status.listening ? 'ok' : 'err'}` },
                    status.listening
                      ? `监听运行中 · ${status.transports.join(' + ') || '?'} · 端口 ${status.boundPorts.join(', ') || '无'} · 已收 ${status.packets} 包`
                      : '监听未运行'),
                  h('div', { style: { marginTop: 8 } },
                    h('button', { className: 'sla-btn', disabled: busy || !status.listening, onClick: () => void controlListener('stop') }, busy ? '处理中…' : '停止 syslog 接收'),
                    status.listening ? null : h('button', { className: 'sla-btn primary', style: { marginLeft: 8 }, disabled: busy, onClick: () => void controlListener('start') }, '启动 syslog 接收'),
                    h('div', { className: 'sla-note', style: { marginTop: 6 } }, '停止只关掉收包套接字：面板、工具、已存告警都还在，随时可再启动。'),
                  ),
                  status.failedPorts.length
                    ? h('div', { className: 'sla-msg err' },
                        '绑定失败：',
                        status.failedPorts.map((f) => `${f.port} → ${f.reason}`).join('；'),
                        h('div', { className: 'sla-note' }, 'Linux 上 514 属于特权端口，需提权或 setcap；可改用 1514 并在设备侧同步改 syslog server 端口。'))
                    : null,
                  status.listening && status.packets === 0
                    ? h('div', { className: 'sla-msg warn' }, '监听已启动但一个包都没收到：检查设备侧 syslog server 地址/端口，以及本机防火墙是否放行入站。')
                    : null,
                )
              : h('div', { className: 'sla-loading' }, '连接宿主…'),
            s
              ? h('div', { className: 'sla-stats' },
                  h('h4', null, '计数'),
                  h('div', { className: 'sla-kv' },
                    h('span', null, '收包'), h('b', null, String(s.received)),
                    h('span', null, '建立告警'), h('b', null, String(s.alertsCreated)),
                    h('span', null, '预过滤丢弃'), h('b', null, String(s.filtered)),
                    h('span', null, '去重'), h('b', null, String(s.deduped)),
                    h('span', null, '限流'), h('b', null, String(s.rateLimited)),
                    h('span', null, '风暴聚合'), h('b', null, String(s.storms)),
                  ),
                  h('h4', null, '设备映射来源'),
                  devices.length === 0
                    ? h('div', { className: 'sla-note' }, 'hillstone 未返回设备列表，来源 IP 无法映射到设备，告警会按「未映射策略」处理。')
                    : h('div', { className: 'sla-note' }, `共 ${devices.length} 台设备，按设备 IP 精确匹配 syslog 来源。设备 syslog 源地址与管理地址不同时需要额外映射规则（当前版本按 IP 匹配）。`),
                )
              : null,
          ),
        ),

    showSettings
      ? h(Settings, { settings: editable, onSave: saveSettings, onClose: () => setShowSettings(false) })
      : null,

    // The detail is a modal now, so "selected" means "the modal is open":
    // closing it clears the selection rather than leaving a row highlighted
    // with nothing shown.
    detail
      ? h(AlertModal, {
          alert: detail,
          onAck: () => void ack(),
          onClose: () => { setDetail(null); setSelectedId(null) },
        })
      : null,
  )
}

// ---- registrations -----------------------------------------------------------

const IconComponent = () => h('svg', { viewBox: '0 0 24 24', width: 18, height: 18, 'aria-hidden': true, style: { display: 'block' } },
  h('path', { fill: 'currentColor', opacity: 0.9, d: 'M12 2 2 20h20L12 2zm0 4 6.8 12H5.2L12 6z' }),
  h('circle', { cx: 12, cy: 15, r: 1.4, fill: 'currentColor' }),
)

export const name = 'dsh-syslog-alert-client'
export const inject = ['slots', 'sidebarRightTabs', 'sidebarRight', 'uiWorkspace']

const TAB_KIND = PANEL_ID

export function apply(ctx: any): void {
  try {
    const unwatch = ctx.inject(['sidebarRightTabs', 'sidebarRight'], () => {
      try {
        ctx.sidebarRightTabs.register({
          id: TAB_KIND,
          kind: TAB_KIND,
          priority: 'extension',
          title: () => '智能告警中心',
          guide: [
            {
              order: 30,
              title: () => '智能告警中心',
              description: () =>
                '接收网络设备发来的 syslog 告警：解析、去重、限流与风暴聚合后进入实时告警流。当天第一条日志新建普通会话交给 agent 分析，结论由 agent 调用 syslog_conclude 写回详情。列表点击行看完整时间线。',
              icon: IconComponent,
            },
          ],
        })
        ctx.slots.inject('sidebar.right.pane.tab', () =>
          ctx.slots.register({ name: 'sidebar.right.pane.tab', key: TAB_KIND, inject: () => ({ api: ctx }) }, AlertCenterPage),
        )
      } catch (error) {
        console.error('[dsh-syslog-alert] right tab registration failed:', error)
      }
    })
    void unwatch
  } catch (error) {
    console.error('[dsh-syslog-alert] client failed to load:', error)
  }
}

// ---- stylesheet --------------------------------------------------------------

const CSS = `
.sla-root { display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 12px 12px 0; box-sizing: border-box; color: var(--dsw-alias-label-primary, #e7e7ea); font-family: inherit; }
.sla-seg { display: inline-flex; align-items: center; gap: 2px; padding: 2px; border-radius: var(--dsw-radius-md, 12px); background: var(--dsw-alias-bg-layer-1, #1a1b1f); border: 1px solid var(--dsw-alias-border-l2, #2a2a36); }
.sla-seg button { border: none; background: transparent; color: var(--dsw-alias-label-tertiary, #9a9aa6); padding: 4px 14px; border-radius: var(--dsw-radius-sm, 8px); cursor: pointer; font-family: inherit; font-size: 13px; line-height: 20px; white-space: nowrap; }
.sla-seg button.on { background: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 18%, transparent); color: var(--dsw-alias-label-primary, #e7e7ea); font-weight: 500; }
.sla-seg button:hover:not(.on) { background: var(--dsw-alias-interactive-bg-hover, #ffffff10); }

.sla-body { flex: 1; min-height: 0; display: flex; gap: 10px; padding: 10px 0 12px; }
.sla-pane { border: 1px solid var(--dsw-alias-border-l2, #2a2a36); border-radius: var(--dsw-radius-md, 12px); background: var(--dsw-alias-bg-layer-1, #1e1f23); min-height: 0; display: flex; flex-direction: column; }
.sla-pane.single { flex: 1; min-width: 0; overflow: auto; padding: 12px; }
/* The alert list is the only pane in its tab now that the detail moved into a
   modal, so it takes the full width and keeps its own inner scroll. */
.sla-pane.list { flex: 1; min-width: 0; overflow: hidden; padding: 0; }

.sla-filters { display: flex; gap: 6px; flex-wrap: wrap; padding: 10px; border-bottom: .5px solid var(--dsw-alias-border-l2, #2a2a36); }
.sla-filters .sla-input { flex: 1; min-width: 96px; }
.sla-rows { flex: 1; min-height: 0; overflow: auto; padding: 6px; }

.sla-row { display: flex; gap: 8px; width: 100%; text-align: left; padding: 8px 9px; margin-bottom: 4px; border: 1px solid transparent; border-radius: var(--dsw-radius-sm, 8px); background: transparent; cursor: pointer; font-family: inherit; color: inherit; }
.sla-row:hover { background: var(--dsw-alias-interactive-bg-hover, #ffffff10); }
.sla-row.on { background: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 10%, transparent); border-color: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 30%, transparent); }
.sla-sev { flex: none; width: 3px; border-radius: 2px; background: var(--dsw-alias-border-l4, #4a4d55); }
.sla-sev.s0, .sla-sev.s3 { background: var(--dsw-alias-state-error-primary, #f85149); }
.sla-sev.s4 { background: var(--dsw-alias-state-warn-label, #dd8629); }
.sla-sev.s5 { background: var(--dsw-alias-state-success-primary, #22c55e); }
.sla-main { min-width: 0; flex: 1; }
.sla-line1 { display: flex; align-items: center; gap: 6px; min-width: 0; }
.sla-line1 b { font-size: 13px; font-weight: 500; color: var(--dsw-alias-label-primary, #f9fafb); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sla-line1 code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11.5px; color: var(--dsw-alias-state-business-primary, #4176e6); flex: none; }
.sla-rep { flex: none; font-size: 11px; color: var(--dsw-alias-state-warn-label, #dd8629); }
.sla-line2 { margin-top: 3px; font-size: 12px; line-height: 17px; color: var(--dsw-alias-label-tertiary, #9a9aa6); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sla-line3 { display: flex; align-items: center; gap: 5px; margin-top: 4px; }
.sla-time { font-size: 11px; color: var(--dsw-alias-label-caption, #81858c); font-variant-numeric: tabular-nums; }

/* Received-at column: a fixed-width right rail so the two lines of every row
   line up vertically. Tabular numerals alone are not enough — the width has to
   be pinned, or a row without a day separator shifts and the column reads
   ragged. */
.sla-col-time { flex: none; width: 62px; text-align: right; font-variant-numeric: tabular-nums; }
.sla-col-time .sla-t-d { display: block; font-size: 11px; line-height: 15px; color: var(--dsw-alias-label-caption, #81858c); }
.sla-col-time .sla-t-t { display: block; font-size: 11.5px; line-height: 15px; color: var(--dsw-alias-label-secondary, #cfd3d6); }
/* The header row is not clickable, so it must not inherit the hover affordance,
   and it sits outside the scrolling row list so it never scrolls away. */
.sla-row.head {
  flex: none; cursor: default; margin: 0 0 2px; padding: 4px 9px;
  font-size: 11px; color: var(--dsw-alias-label-caption, #81858c);
  border-bottom: .5px solid var(--dsw-alias-border-l2, #2a2a36);
}
.sla-row.head:hover { background: transparent; }

.sla-badge { flex: none; padding: 1px 6px; border-radius: var(--dsw-radius-xs, 4px); font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-secondary, #cfd3d6); background: color-mix(in srgb, var(--dsw-alias-label-tertiary, #9a9aa6) 16%, transparent); }
.sla-badge.v { color: var(--dsw-alias-state-business-primary, #4176e6); background: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 14%, transparent); }
.sla-badge.ok { color: var(--dsw-alias-state-success-primary, #22c55e); background: color-mix(in srgb, var(--dsw-alias-state-success-primary, #22c55e) 14%, transparent); }
.sla-badge.err { color: var(--dsw-alias-state-error-primary, #f85149); background: color-mix(in srgb, var(--dsw-alias-state-error-primary, #f85149) 14%, transparent); }
.sla-badge.warn { color: var(--dsw-alias-state-warn-label, #dd8629); background: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 14%, transparent); }

.sla-detail { padding: 12px; }
.sla-dhead { display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.sla-dtitle { display: flex; align-items: center; gap: 7px; font-size: 14px; font-weight: 600; }
.sla-dtitle code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; font-weight: 400; color: var(--dsw-alias-state-business-primary, #4176e6); }
.sla-dmeta { margin-top: 4px; font-size: 11.5px; line-height: 17px; color: var(--dsw-alias-label-caption, #81858c); }
.sla-dacts { display: flex; gap: 6px; align-items: center; }

.sla-block { margin-top: 10px; border: 1px solid var(--dsw-alias-border-l2, #2a2a36); border-radius: var(--dsw-radius-sm, 8px); background: var(--dsw-alias-bg-layer-2, #232324); padding: 9px 11px; }
.sla-block.err { border-color: color-mix(in srgb, var(--dsw-alias-state-error-primary, #f85149) 30%, transparent); }
.sla-block.ok { border-color: color-mix(in srgb, var(--dsw-alias-state-success-primary, #22c55e) 26%, transparent); }
.sla-block.warn { border-color: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 28%, transparent); }
.sla-block-t { margin: 0 0 7px; font-size: 12px; line-height: 18px; font-weight: 600; color: var(--dsw-alias-label-secondary, #cfd3d6); }
.sla-p { margin: 0 0 5px; font-size: 12.5px; line-height: 19px; color: var(--dsw-alias-label-primary, #f9fafb); white-space: pre-wrap; word-break: break-word; }
.sla-p.sub { font-size: 11.5px; color: var(--dsw-alias-label-caption, #81858c); }

.sla-pre { margin: 0; max-height: 320px; overflow: auto; padding: 8px 10px; border-radius: var(--dsw-radius-xs, 4px); background: var(--dsw-alias-bg-layer-1, #0d0d12); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11.5px; line-height: 17px; color: var(--dsw-alias-label-secondary, #cfd3d6); white-space: pre-wrap; word-break: break-word; }

.sla-tl { margin-top: 2px; }
.sla-tl-row { display: flex; align-items: baseline; gap: 7px; padding: 3px 0; border-top: .5px solid var(--dsw-alias-border-l1, #ffffff0f); font-size: 11.5px; line-height: 17px; }
.sla-tl-t { flex: none; color: var(--dsw-alias-label-caption, #81858c); font-variant-numeric: tabular-nums; }
.sla-tl-s { flex: none; min-width: 60px; color: var(--dsw-alias-label-secondary, #cfd3d6); }
.sla-tl-n { flex: 1; min-width: 0; color: var(--dsw-alias-label-tertiary, #9a9aa6); word-break: break-word; }
.sla-tl-d { flex: none; color: var(--dsw-alias-label-caption, #81858c); font-variant-numeric: tabular-nums; }

.sla-warn-box { margin-bottom: 8px; padding: 7px 10px; border-radius: var(--dsw-radius-sm, 6px); font-size: 12px; line-height: 18px; color: var(--dsw-alias-state-warn-label, #dd8629); background: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 10%, transparent); border: 1px solid color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 26%, transparent); }

.sla-msg { margin: 8px 0 0; padding: 8px 11px; border-radius: var(--dsw-radius-sm, 6px); font-size: 12px; line-height: 18px; border: 1px solid var(--dsw-alias-border-l2, #2a2a36); }
.sla-msg code { word-break: break-all; }
.sla-msg.ok { color: var(--dsw-alias-state-success-primary, #22c55e); background: color-mix(in srgb, var(--dsw-alias-state-success-primary, #22c55e) 10%, transparent); border-color: color-mix(in srgb, var(--dsw-alias-state-success-primary, #22c55e) 28%, transparent); }
.sla-msg.warn { color: var(--dsw-alias-state-warn-label, #dd8629); background: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 10%, transparent); border-color: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 28%, transparent); }
.sla-msg.err { color: var(--dsw-alias-state-error-primary, #f85149); background: color-mix(in srgb, var(--dsw-alias-state-error-primary, #f85149) 10%, transparent); border-color: color-mix(in srgb, var(--dsw-alias-state-error-primary, #f85149) 28%, transparent); }
.sla-acts { display: flex; gap: 6px; margin-top: 7px; }

.sla-note { margin: 6px 0; font-size: 11.5px; line-height: 18px; color: var(--dsw-alias-label-caption, #81858c); }
.sla-empty { margin: 10px; padding: 26px 16px; text-align: center; border: 1.5px dashed var(--dsw-alias-border-l3, #3a414b); border-radius: var(--dsw-radius-md, 12px); font-size: 12.5px; line-height: 20px; color: var(--dsw-alias-label-tertiary, #9a9aa6); }
.sla-empty b { display: block; margin-bottom: 4px; font-size: 13.5px; color: var(--dsw-alias-label-primary, #f9fafb); }
.sla-loading { padding: 18px 2px; font-size: 12.5px; color: var(--dsw-alias-label-tertiary, #9a9aa6); }

.sla-test { flex: none; padding: 9px 10px; border-top: .5px solid var(--dsw-alias-border-l2, #2a2a36); }
.sla-test-row { display: flex; gap: 6px; }
.sla-test-row .sla-input:first-child { flex: 1; min-width: 0; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11.5px; }

.sla-btn { display: inline-flex; align-items: center; justify-content: center; gap: 4px; padding: 4px 12px; border-radius: var(--dsw-radius-sm, 8px); border: 1px solid var(--dsw-alias-border-l2, #3a414b); background: color-mix(in srgb, var(--dsw-alias-bg-layer-3, #2c2c2e) 55%, transparent); color: var(--dsw-alias-label-secondary, #cfd3d6); cursor: pointer; font-family: inherit; font-size: 13px; line-height: 20px; white-space: nowrap; }
.sla-btn:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover, #ffffff14); color: var(--dsw-alias-label-primary, #f9fafb); }
.sla-btn:disabled { opacity: .5; cursor: default; }
.sla-btn.primary { color: var(--dsw-alias-state-business-primary, #4176e6); border-color: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 30%, transparent); background: color-mix(in srgb, var(--dsw-alias-state-business-primary, #4176e6) 8%, transparent); }
.sla-btn.plain { background: transparent; border-color: transparent; color: var(--dsw-alias-label-tertiary, #9a9aa6); }

.sla-input { box-sizing: border-box; width: 100%; padding: 4px 9px; border-radius: var(--dsw-radius-sm, 8px); border: 1px solid var(--dsw-alias-border-l2, #3a414b); background: var(--dsw-alias-bg-layer-2, #232324); color: var(--dsw-alias-label-primary, #f9fafb); font-family: inherit; font-size: 12.5px; line-height: 19px; outline: none; }
.sla-input:focus { border-color: var(--dsw-alias-state-business-primary, #4176e6); }
/* The prompt is multi-line by nature: one line would hide whether the operator's
   instruction still ends where the appended alert context begins. */
.sla-textarea { min-height: 62px; resize: vertical; line-height: 18px; white-space: pre-wrap; }
select.sla-input { appearance: auto; cursor: pointer; }
select.sla-input option { background: var(--dsw-alias-bg-layer-2, #232324); color: var(--dsw-alias-label-primary, #f9fafb); }
.sla-cb { width: 16px; height: 16px; accent-color: var(--dsw-alias-state-business-primary, #4176e6); cursor: pointer; }

.sla-field { margin-bottom: 11px; }
.sla-field.row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.sla-field label { display: block; margin-bottom: 5px; font-size: 12.5px; line-height: 18px; color: var(--dsw-alias-label-secondary, #cfd3d6); }
.sla-field.row label { margin-bottom: 0; }
.sla-field label i { font-style: normal; margin-left: 4px; font-size: 11.5px; color: var(--dsw-alias-label-caption, #81858c); }
.sla-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0 11px; }

.sla-scrim { position: fixed; inset: 0; z-index: 1100; display: flex; align-items: center; justify-content: center; background: var(--dsw-alias-bg-mask-2, #00000008); }
.sla-modal { width: min(520px, 92vw); max-height: 86vh; display: flex; flex-direction: column; border: 1px solid var(--dsw-alias-border-l2, #2a2a36); border-radius: var(--dsw-radius-lg, 16px); background: var(--dsw-alias-bg-layer-1, #232324); box-shadow: var(--dsw-shadow-lv4, 0 16px 48px 0 #00000033); overflow: hidden; }
/* The alert timeline is mostly a wall of monospace blocks; the 520px sheet the
   settings form uses would wrap every command and make it unreadable. */
.sla-modal-wide { width: min(880px, 94vw); }
.sla-modal-wide .sla-modal-body { padding: 0; }
.sla-modal-wide .sla-modal-foot { justify-content: flex-end; }
.sla-modal-head { display: flex; align-items: center; justify-content: space-between; padding: 13px 16px; border-bottom: .5px solid var(--dsw-alias-border-l1, #ffffff0f); }
.sla-modal-head b { font-size: 14px; font-weight: 600; }
.sla-x { border: none; background: transparent; color: var(--dsw-alias-label-tertiary, #9a9aa6); font-size: 18px; cursor: pointer; line-height: 1; }
.sla-modal-body { flex: 1; min-height: 0; overflow: auto; padding: 13px 16px; }
.sla-modal-foot { display: flex; gap: 8px; justify-content: flex-end; padding: 12px 16px; border-top: .5px solid var(--dsw-alias-border-l1, #ffffff0f); background: var(--dsw-alias-bg-layer-2, #2c2c2e); }

.sla-stats h4 { margin: 14px 0 7px; font-size: 12.5px; font-weight: 600; color: var(--dsw-alias-label-secondary, #cfd3d6); }
.sla-stats h4:first-child { margin-top: 2px; }
.sla-kv { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 4px 12px; font-size: 12.5px; }
.sla-kv span { color: var(--dsw-alias-label-tertiary, #9a9aa6); }
.sla-kv b { font-weight: 600; font-variant-numeric: tabular-nums; }
`
