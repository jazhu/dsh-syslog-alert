/**
 * One-off probe: what does the running DSH report about the alert-day session —
 * the settings it is running with, and the session it actually opened?
 *
 * Run from the DSH GUI session: node test/providers.now.mjs
 * It talks to the host only through /syslog-api, i.e. the same surface the
 * settings dialog would use.
 *
 * Read `/status` first: `autoSession.workspace` is the directory the live
 * session ended up in, which is not necessarily the one in `config` — a blank
 * or non-absolute setting falls back to the host's current workspace.
 */
const API = 'http://127.0.0.1:18784/syslog-api'

const j = await fetch(`${API}/_session`).then((r) => r.json()).catch((e) => ({ error: String(e) }))
const token = typeof j.token === 'string' ? j.token : ''
if (!token) {
  console.error('no token from /_session:', JSON.stringify(j).slice(0, 200))
  console.error('is the plugin enabled in this profile?')
  process.exit(1)
}
const headers = { 'X-Syslog-Token': token }

for (const path of ['/status', '/auto-session']) {
  const r = await fetch(`${API}${path}`, { headers }).then((res) => res.json())
  console.log(`\n=== ${path}`)
  console.log(JSON.stringify(r, null, 2))
}