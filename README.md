# Smart Alert Center (`dsh-syslog-alert`)

Runs a UDP/TCP syslog receiver **inside DSH** and ingests every device alert in real
time: parse → pre-filter → fingerprint dedup → per-device rate limit → alert record →
delivery to the alert session of the day. Alerts stream into the panel; click a row for
the alert's full timeline.

**Analysis is delegated to the session's agent.** The plugin itself makes no model calls:
the day's first log opens an ordinary session, later logs are posted into it, and the
agent analyses them and calls the `syslog_conclude` tool to write its conclusion back
onto the alert detail.

> 中文说明见 [README-zh.md](./README-zh.md)。

## Requirements

- DSH with `sessionController` available (built into the host; the alert-day session
  needs no provider and no model choice)
- Node 22.19+ or 24+ (DSH's bundled runtime qualifies)

## Install

```bash
dsh plugin add /path/to/dsh-syslog-alert-0.1.0.tgz
```

Then open the plugin's settings and set the listening ports (default UDP+TCP 1514), and
point your devices' syslog forwarder at the DSH host's address.

## How it works

```
socket → parse → pre-filter → fingerprint dedup → per-device rate limit
       → alert record → day-session delivery → SSE
```

The ingestion path is entirely synchronous and cheap. Four independent brakes protect
against a link flap that emits thousands of lines: pre-filtering, fingerprint dedup, a
per-device per-minute rate limit, and storm aggregation. Analysis is not on the
ingestion path — it happens in the alert session of the day, done by the agent.

## Safety model

- Log text always enters the prompt inside a fence labelled as **data**, never mixed
  with instructions; the day session shares one defanger, so a forged closing fence is
  rewritten out of effect.
- The alert id, device name, and raw log are appended by the plugin itself; a custom
  prompt from settings can only replace the instruction line, and nothing in the log can
  displace them.
- A frame whose sender is not a mapped device follows the unmapped policy — stored and
  flagged by default.
- Frames that cannot be confidently parsed are stored and shown, never used as
  structured fields.

## Panel

The "智能告警中心" sidebar panel has three tabs:

| Tab | Contents |
| --- | --- |
| **Alerts** | Full-width list: severity bar, device/tag, excerpt, status badges, and a **received-at** column on the right. Clicking a row opens the detail in a modal (close with Esc or by clicking the scrim). |
| **Self-test** | Inject one frame by hand and run it through the whole pipeline (parse → mapping → prefilter → day session). |
| **Status** | Listener state and start/stop, counters, device mapping source. |

The detail is a modal rather than a side pane: a pane can only take half the width, and the
detail body is mostly monospace log output that wraps on every line at 46%.

## Configuration

Set from the in-app settings panel: ports and transports, device source mapping, and the
alert session of the day (title prefix, workspace, prompt).

### The alert session: one ordinary session per day

The day's first log creates an **ordinary session** titled `<prefix> <local date>` (default
`告警分析 2026-10-07`), and every later log is appended to it as one more message. Each message is
the instruction line, then the alert id, the device name, and the raw syslog — plus a
request for the session agent to call the `syslog_conclude` tool with its conclusion once it
has finished analysing. The conclusion shows up in the alert detail's "当日会话分析结论"
block. This is the only path a conclusion takes into the alert detail: the plugin never
reads the session transcript (that is not a public host surface), so if the agent skips
the tool the detail stays without one.

Three fields under the switch:

| Setting | Description | Default |
| --- | --- | --- |
| **Enable agent online analysis** | Turns the day session above on. With it off the plugin only ingests and records; no session is opened. | **on** |
| Day-session title prefix | The title's prefix; blank falls back to `告警分析`. | `告警分析` |
| Day-session workspace | The workspace the session is created in; **must be an absolute path** (`D:\...` or `/...`). Blank or invalid falls back to the host's current workspace, noted in the status. | blank (host's current workspace) |
| Session prompt | Replaces the prompt's **instruction line**. `{id}` (alert id) and `{device}` (device name) are placeholders; the alert id, device name, and the fenced raw log are always appended by the plugin, and nothing in the log can displace them. Blank means the default instruction `分析这条日志`. | `分析这条日志` |

It works with no configuration at all: the session rides the host's `sessionController`
(built into DSH) and **consumes no subagent provider and needs no model choice**. The host owns
the session — open, rename, or delete it any time from the session list; after a plugin
reload `auto-session.json` re-adopts the day's session instead of opening a second one.

> The workspace and prompt take effect **when the session is created**: today's already-open
> session is kept as is, and a settings change only affects sessions opened later.
> The workspace today's session actually lives in is in the status's `workspace` field — it can
> differ from the setting (blank means the host's current workspace).

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| No alerts arrive | Check the panel's **bound ports**; a bind failure (e.g. port 514 needs privileges on Linux) is reported as a failed port, never silently. Verify the device's syslog target address and the firewall. |
| The detail has no "当日会话分析结论" | The conclusion is written back by the session agent calling `syslog_conclude`. After a successful delivery the detail first shows "会话分析中"; if it stays there, the agent never called the tool (check whether it reported the tool as unavailable in the session), or the alert has already rolled out of the in-memory ring. |
| The alert session was never created | The panel's status carries the reason: the switch is off (当日会话未启用), the host provides no `sessionController` service, or the day's first log has not arrived yet. `GET /syslog-api/auto-session` shows the same state. |
| The session title is not my prefix | An empty prefix falls back to `告警分析`. The title carries the LOCAL date, so the first log after midnight starts a new session. |
| The session opened in the wrong workspace | A workspace that is not an absolute path is ignored (DSH's `cwd` accepts absolute paths only); the plugin falls back to the host's current workspace and logs it. A session already open today is not moved — the change takes effect on the next day, or after `auto-session.json` is cleared. |
| The prompt is not what I typed | Only the instruction line is replaced; `{id}` and `{device}` are placeholders. Blank means the default `分析这条日志`. Remember that workspace/prompt changes only apply to sessions opened later. |
| Changes not visible | Fully quit and restart the DSH client — the plugin bundle is cached by the module loader. |

## License

MIT
