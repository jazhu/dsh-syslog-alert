window.__ModuleLoader__.load({ id: 'dsh-syslog-alert', factory: (require) => { var module = { exports: {} }; var exports = module.exports;
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name2 in all)
    __defProp(target, name2, { get: all[name2], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client.tsx
var client_exports = {};
__export(client_exports, {
  apply: () => apply,
  inject: () => inject,
  name: () => name
});
module.exports = __toCommonJS(client_exports);
var import_react = require("react");
var PANEL_ID = "dsh-syslog-alert";
var API_PORT = 18784;
var API = `http://127.0.0.1:${API_PORT}/syslog-api`;
var TOKEN_KEY = "dsh-syslog-alert-token";
var SEVERITY_LABELS = ["\u7D27\u6025", "\u4E25\u91CD", "\u4E25\u91CD", "\u9519\u8BEF", "\u8B66\u544A", "\u901A\u77E5", "\u4FE1\u606F", "\u8C03\u8BD5"];
var AUTO_SESSION_PROMPT = "\u5206\u6790\u8FD9\u6761\u65E5\u5FD7";
function isAbsolutePath(value) {
  return /^(?:[A-Za-z]:[\\/]|\/)/.test(String(value ?? "").trim());
}
var STAGE_LABELS = {
  received: "\u5DF2\u63A5\u6536",
  mapped: "\u5DF2\u6620\u5C04",
  filtered: "\u4EC5\u7559\u5B58",
  deduped: "\u53BB\u91CD/\u98CE\u66B4",
  closed: "\u5DF2\u5173\u95ED",
  failed: "\u5931\u8D25"
};
var cssInjected = false;
function injectStyles() {
  if (cssInjected || typeof document === "undefined") return;
  cssInjected = true;
  const el = document.createElement("style");
  el.setAttribute("data-syslog-alert", "");
  el.textContent = CSS;
  document.head.appendChild(el);
}
var sessionToken = null;
var tokenProbed = false;
var manualToken = null;
var tokenNotice = null;
async function bootstrapToken() {
  if (tokenProbed) return manualToken ?? sessionToken ?? "";
  tokenProbed = true;
  let stored = null;
  try {
    stored = localStorage.getItem(TOKEN_KEY);
  } catch {
  }
  if (stored) {
    manualToken = stored;
    return stored;
  }
  try {
    const r = await fetch(API + "/_session");
    const j = await r.json();
    if (j.enabled && j.token) sessionToken = j.token;
  } catch {
  }
  return manualToken ?? sessionToken ?? "";
}
async function api(path, opts = {}) {
  const token = await bootstrapToken();
  const headers = { "content-type": "application/json" };
  if (token) headers["X-Syslog-Token"] = token;
  const res = await fetch(API + path, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== void 0 ? JSON.stringify(opts.body) : void 0
  });
  if (res.status === 401) {
    const reason = "\u667A\u80FD\u544A\u8B66\u4E2D\u5FC3\u8BBF\u95EE\u4EE4\u724C\u7F3A\u5931\u6216\u65E0\u6548\u3002host \u5DF2\u653E\u884C\u672C\u673A\u6765\u6E90\uFF1B\u82E5\u4ECD\u62A5\u9519\uFF0C\u8BF7\u7C98\u8D34\u672C\u673A\u4EE4\u724C\u540E\u91CD\u8BD5\u3002";
    tokenNotice?.(reason);
    throw new Error(reason);
  }
  const j = await res.json();
  if (j.ok === false && j.error) throw new Error(j.error.message ?? "request failed");
  return j;
}
var DEFAULT_FILTERS = { severityMax: 7, deviceId: "", stage: "", search: "", sinceMinutes: 0 };
function mergeAlert(list, incoming) {
  const idx = list.findIndex((a) => a.id === incoming.id);
  if (idx < 0) return [incoming, ...list];
  const next = list.slice();
  next[idx] = incoming;
  return next;
}
function sevClass(sev) {
  if (sev <= 2) return "s0";
  if (sev === 3) return "s3";
  if (sev === 4) return "s4";
  return "s5";
}
function fmtDay(at) {
  const d = new Date(at);
  return `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
function fmtClock(at) {
  const d = new Date(at);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}
function AlertListHead() {
  return (0, import_react.createElement)(
    "div",
    { className: "sla-row head" },
    (0, import_react.createElement)("span", { className: "sla-sev" }),
    (0, import_react.createElement)("div", { className: "sla-main" }, "\u8BBE\u5907 / \u6458\u8981"),
    (0, import_react.createElement)("div", { className: "sla-col-time" }, "\u63A5\u6536\u65F6\u95F4")
  );
}
function AlertRow(props) {
  const { alert, selected, onSelect } = props;
  const sev = alert.message.severity ?? 7;
  const excerpt = alert.message.message.replace(/\s+/g, " ").slice(0, 160);
  return (0, import_react.createElement)(
    "button",
    { className: `sla-row${selected ? " on" : ""}`, onClick: onSelect },
    (0, import_react.createElement)("span", { className: `sla-sev ${sevClass(sev)}` }),
    (0, import_react.createElement)(
      "div",
      { className: "sla-main" },
      (0, import_react.createElement)(
        "div",
        { className: "sla-line1" },
        (0, import_react.createElement)("b", null, alert.deviceName ?? "\u672A\u6620\u5C04\u8BBE\u5907"),
        alert.message.tag ? (0, import_react.createElement)("code", null, alert.message.tag) : null,
        alert.count > 1 ? (0, import_react.createElement)("span", { className: "sla-rep" }, `\xD7${alert.count}`) : null
      ),
      (0, import_react.createElement)("div", { className: "sla-line2" }, excerpt),
      (0, import_react.createElement)(
        "div",
        { className: "sla-line3" },
        (0, import_react.createElement)("span", { className: "sla-badge" }, STAGE_LABELS[alert.stage] ?? alert.stage),
        alert.sessionConclusion || alert.analysisPending ? (0, import_react.createElement)("span", { className: `sla-badge v${alert.analysisPending ? " warn" : ""}` }, alert.analysisPending ? "\u5206\u6790\u4E2D" : "\u6709\u7ED3\u8BBA") : null
      )
    ),
    (0, import_react.createElement)(
      "div",
      { className: "sla-col-time" },
      (0, import_react.createElement)("span", { className: "sla-t-d" }, fmtDay(alert.receivedAt)),
      (0, import_react.createElement)("span", { className: "sla-t-t" }, fmtClock(alert.receivedAt))
    )
  );
}
function Block(props) {
  return (0, import_react.createElement)(
    "section",
    { className: `sla-block${props.tone ? " " + props.tone : ""}` },
    (0, import_react.createElement)("h4", { className: "sla-block-t" }, props.title),
    props.children
  );
}
function AlertDetail(props) {
  const { alert, onAck } = props;
  const m = alert.message;
  return (0, import_react.createElement)(
    "div",
    { className: "sla-detail" },
    (0, import_react.createElement)(
      "div",
      { className: "sla-dhead" },
      (0, import_react.createElement)(
        "div",
        null,
        (0, import_react.createElement)(
          "div",
          { className: "sla-dtitle" },
          (0, import_react.createElement)("span", { className: `sla-sev ${sevClass(m.severity ?? 7)}`, style: { height: 14, borderRadius: 3 } }),
          alert.deviceName ?? "\u672A\u6620\u5C04\u8BBE\u5907",
          m.tag ? (0, import_react.createElement)("code", null, m.tag) : null
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-dmeta" },
          `${new Date(alert.receivedAt).toLocaleString("zh-CN", { hour12: false })}`,
          ` \xB7 \u6765\u6E90 ${alert.sourceIp ?? "?"}`,
          ` \xB7 ${alert.transport?.toUpperCase() ?? "?"}`,
          ` \xB7 \u7EA7\u522B ${m.severityName ?? SEVERITY_LABELS[m.severity ?? 7] ?? "?"}`,
          ` \xB7 \u89E3\u6790\u53EF\u4FE1\u5EA6 ${m.confidence}`,
          alert.count > 1 ? ` \xB7 \u91CD\u590D ${alert.count} \u6B21` : ""
        )
      ),
      (0, import_react.createElement)(
        "div",
        { className: "sla-dacts" },
        alert.ackedAt ? (0, import_react.createElement)("span", { className: "sla-badge" }, "\u5DF2\u786E\u8BA4") : (0, import_react.createElement)("button", { className: "sla-btn plain", onClick: onAck }, "\u786E\u8BA4")
      )
    ),
    m.confidence === "raw" ? (0, import_react.createElement)("div", { className: "sla-warn-box" }, "\u8FD9\u6761\u65E5\u5FD7\u65E0\u6CD5\u8BC6\u522B\u4E3A RFC3164/5424\uFF0C\u7ED3\u6784\u5316\u5B57\u6BB5\u4E0D\u53EF\u4FE1\u3002\u539F\u59CB\u6587\u672C\u89C1\u4E0B\u3002") : null,
    alert.dropReason ? (0, import_react.createElement)("div", { className: "sla-warn-box" }, `\u672A\u8FDB\u5165\u5206\u6790\uFF1A${alert.dropDetail ?? alert.dropReason}`) : null,
    (0, import_react.createElement)(Block, { key: "raw", title: "\u539F\u59CB syslog", children: (0, import_react.createElement)("pre", { className: "sla-pre" }, m.raw) }),
    alert.sessionConclusion || alert.analysisPending ? (0, import_react.createElement)(Block, {
      key: "session",
      title: alert.analysisPending ? "\u4F1A\u8BDD\u5206\u6790\u4E2D" : "\u4F1A\u8BDD\u5206\u6790\u7ED3\u8BBA",
      tone: alert.analysisPending ? "warn" : "ok",
      children: (0, import_react.createElement)(
        "div",
        null,
        alert.sessionConclusion ? (0, import_react.createElement)("p", { className: "sla-p" }, alert.sessionConclusion) : (0, import_react.createElement)("p", { className: "sla-p sub" }, "\u5DF2\u6295\u9012\u5230\u5F53\u65E5\u4F1A\u8BDD\uFF0C\u7B49\u5F85 agent \u5206\u6790\u5E76\u8C03\u7528 syslog_conclude \u5199\u56DE\u2026"),
        (0, import_react.createElement)(
          "p",
          { className: "sla-p sub" },
          alert.sessionId ? `\u4F1A\u8BDD ${alert.sessionId.slice(0, 8)}` : "",
          alert.sessionConclusionAt ? ` \xB7 \u63D0\u53D6\u4E8E ${new Date(alert.sessionConclusionAt).toLocaleString("zh-CN", { hour12: false })}` : ""
        )
      )
    }) : null,
    (0, import_react.createElement)(Block, {
      key: "timeline",
      title: "\u5904\u7406\u65F6\u95F4\u7EBF",
      children: (0, import_react.createElement)(
        "div",
        { className: "sla-tl" },
        alert.timeline.map(
          (t, i) => (0, import_react.createElement)(
            "div",
            { key: i, className: "sla-tl-row" },
            (0, import_react.createElement)("span", { className: "sla-tl-t" }, new Date(t.at).toLocaleTimeString("zh-CN", { hour12: false })),
            (0, import_react.createElement)("span", { className: "sla-tl-s" }, STAGE_LABELS[t.stage] ?? t.stage),
            (0, import_react.createElement)("span", { className: "sla-tl-n" }, t.note),
            t.durationMs !== void 0 ? (0, import_react.createElement)("span", { className: "sla-tl-d" }, `${t.durationMs}ms`) : null
          )
        )
      )
    })
  );
}
function AlertModal(props) {
  const { alert, onAck, onClose } = props;
  (0, import_react.useEffect)(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (0, import_react.createElement)(
    "div",
    { className: "sla-scrim", onClick: (e) => {
      if (e.target === e.currentTarget) onClose();
    } },
    (0, import_react.createElement)(
      "div",
      { className: "sla-modal sla-modal-wide", onClick: (e) => e.stopPropagation() },
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-head" },
        (0, import_react.createElement)("b", null, `${alert.deviceName ?? "\u672A\u6620\u5C04\u8BBE\u5907"}${alert.message.tag ? " \xB7 " + alert.message.tag : ""}`),
        (0, import_react.createElement)("button", { className: "sla-x", onClick: onClose }, "\xD7")
      ),
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-body" },
        (0, import_react.createElement)(AlertDetail, { alert, onAck })
      ),
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-foot" },
        (0, import_react.createElement)("button", { className: "sla-btn", onClick: onClose }, "\u5173\u95ED")
      )
    )
  );
}
function Settings(props) {
  const [draft, setDraft] = (0, import_react.useState)(props.settings);
  const [busy, setBusy] = (0, import_react.useState)(false);
  const [err, setErr] = (0, import_react.useState)(null);
  const set = (k, v) => setDraft((d) => ({ ...d, [k]: v }));
  const num = (k, v) => setDraft((d) => ({ ...d, [k]: v === "" ? void 0 : Math.max(0, Number(v)) }));
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await props.onSave(draft);
      props.onClose();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (0, import_react.createElement)(
    "div",
    { className: "sla-scrim", onClick: (e) => {
      if (e.target === e.currentTarget) props.onClose();
    } },
    (0, import_react.createElement)(
      "div",
      { className: "sla-modal" },
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-head" },
        (0, import_react.createElement)("b", null, "\u667A\u80FD\u544A\u8B66\u4E2D\u5FC3\u8BBE\u7F6E"),
        (0, import_react.createElement)("button", { className: "sla-x", onClick: props.onClose }, "\xD7")
      ),
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-body" },
        err ? (0, import_react.createElement)("div", { className: "sla-msg err" }, err) : null,
        (0, import_react.createElement)(
          "div",
          { className: "sla-note" },
          "\u7AEF\u53E3\u4E0E\u4F20\u8F93\u6539\u52A8\u4F1A\u91CD\u542F\u76D1\u542C\uFF08\u4F1A\u77ED\u6682\u4E2D\u65AD\u6536\u5305\uFF09\u3002apiPort / dataDir \u7531\u5BBF\u4E3B\u7BA1\u7406\uFF0C\u6B64\u5904\u4E0D\u53EF\u6539\u3002"
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u76D1\u542C\u7AEF\u53E3", (0, import_react.createElement)("i", null, "\u9017\u53F7\u5206\u9694\uFF1BLinux \u4E0B 514 \u9700\u63D0\u6743\uFF0C\u7ED1\u4E0D\u4E0A\u4F1A\u663E\u793A\u539F\u56E0")),
          (0, import_react.createElement)("input", { className: "sla-input", value: (draft.syslogPorts ?? []).join(","), onChange: (e) => set("syslogPorts", String(e.target.value ?? "").split(",").map((x) => Number(x.trim())).filter((n) => Number.isFinite(n) && n > 0)) })
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u540C\u65F6\u542F\u7528 TCP \u63A5\u6536"),
          (0, import_react.createElement)("input", { type: "checkbox", className: "sla-cb", checked: draft.enableTcp === true, onChange: (e) => set("enableTcp", e.target.checked) })
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u672A\u6620\u5C04\u6765\u6E90\u7B56\u7565"),
          (0, import_react.createElement)(
            "select",
            { className: "sla-input", value: draft.unmappedPolicy ?? "ignore", onChange: (e) => set("unmappedPolicy", e.target.value) },
            (0, import_react.createElement)("option", { value: "ignore" }, "\u5FFD\u7565\u4E22\u5F03"),
            (0, import_react.createElement)("option", { value: "capture-only" }, "\u6536\u4E0B\u6807\u7EA2\u4F46\u7EDD\u4E0D\u5206\u6790")
          )
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "hillstone \u8FD0\u7EF4 API \u7AEF\u53E3", (0, import_react.createElement)("i", null, "\u7559 0 = \u81EA\u52A8\u63A2\u6D4B\u3002\u8BBE\u5907\u5217\u8868\u4E0E SSH \u91C7\u96C6\u90FD\u8D70\u5B83")),
          (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 0, max: 65535, value: draft.opsApiPort ?? 0, onChange: (e) => num("opsApiPort", e.target.value) })
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u6700\u4F4E\u7EA7\u522B", (0, import_react.createElement)("i", null, "0=emerg \u6700\u4E25\u91CD\uFF1B\u9AD8\u4E8E\u8BE5\u503C\u76F4\u63A5\u4E22\u5F03")),
          (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 0, max: 7, value: draft.minSeverity ?? 5, onChange: (e) => num("minSeverity", e.target.value) })
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "mnemonic \u767D\u540D\u5355", (0, import_react.createElement)("i", null, "\u9017\u53F7\u5206\u9694\uFF1B\u7559\u7A7A = \u4E0D\u9650")),
          (0, import_react.createElement)("input", { className: "sla-input", value: (draft.mnemonicAllow ?? []).join(","), onChange: (e) => set("mnemonicAllow", String(e.target.value ?? "").split(",").map((x) => x.trim()).filter(Boolean)) })
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-grid2" },
          (0, import_react.createElement)(
            "div",
            { className: "sla-field" },
            (0, import_react.createElement)("label", null, "\u53BB\u91CD\u7A97\u53E3\uFF08\u79D2\uFF09"),
            (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 0, value: draft.dedupWindowSec ?? 120, onChange: (e) => num("dedupWindowSec", e.target.value) })
          ),
          (0, import_react.createElement)(
            "div",
            { className: "sla-field" },
            (0, import_react.createElement)("label", null, "\u6BCF\u8BBE\u5907\u6BCF\u5206\u949F\u4E0A\u9650"),
            (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 0, value: draft.perDeviceRatePerMin ?? 20, onChange: (e) => num("perDeviceRatePerMin", e.target.value) })
          ),
          (0, import_react.createElement)(
            "div",
            { className: "sla-field" },
            (0, import_react.createElement)("label", null, "\u98CE\u66B4\u9608\u503C", (0, import_react.createElement)("i", null, "\u7A97\u53E3\u5185\u91CD\u590D\u8FBE\u6B64\u6570\u5373\u805A\u5408\u6210\u4E00\u6761")),
            (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 0, value: draft.stormThreshold ?? 5, onChange: (e) => num("stormThreshold", e.target.value) })
          ),
          (0, import_react.createElement)(
            "div",
            { className: "sla-field" },
            (0, import_react.createElement)("label", null, "\u4FDD\u7559\u5929\u6570"),
            (0, import_react.createElement)("input", { className: "sla-input", type: "number", min: 1, value: draft.retentionDays ?? 14, onChange: (e) => num("retentionDays", e.target.value) })
          )
        ),
        (0, import_react.createElement)(
          "div",
          { className: "sla-grid2" },
          (0, import_react.createElement)(
            "div",
            { className: "sla-field row" },
            (0, import_react.createElement)("label", null, "\u542F\u7528 agent \u5728\u7EBF\u5206\u6790", (0, import_react.createElement)("i", null, "\u5F53\u5929\u7B2C\u4E00\u6761\u65E5\u5FD7\u65B0\u5EFA\u666E\u901A\u4F1A\u8BDD\uFF0C\u540E\u7EED\u65E5\u5FD7\u63A5\u7740\u6295\u9012\uFF1B\u65E0\u9700 provider")),
            (0, import_react.createElement)("input", { type: "checkbox", className: "sla-cb", checked: draft.autoSessionEnabled !== false, onChange: (e) => set("autoSessionEnabled", e.target.checked) })
          )
        ),
        draft.autoSessionEnabled !== false ? (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u5F53\u65E5\u4F1A\u8BDD\u6807\u9898\u524D\u7F00", (0, import_react.createElement)("i", null, "\u4F1A\u8BDD\u6807\u9898\u4E3A\u300C\u524D\u7F00 + \u672C\u5730\u65E5\u671F\u300D\uFF1B\u7559\u7A7A\u5219\u7528 \u544A\u8B66\u5206\u6790")),
          (0, import_react.createElement)("input", { className: "sla-input", value: draft.autoSessionTitle ?? "", onChange: (e) => set("autoSessionTitle", String(e.target.value ?? "")), placeholder: "\u544A\u8B66\u5206\u6790" })
        ) : null,
        draft.autoSessionEnabled !== false ? (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u5F53\u65E5\u4F1A\u8BDD\u5DE5\u4F5C\u533A", (0, import_react.createElement)("i", null, "\u4F1A\u8BDD\u521B\u5EFA\u6240\u5728\u7684\u7EDD\u5BF9\u8DEF\u5F84\uFF1B\u7559\u7A7A = \u7528\u5BBF\u4E3B\u5F53\u524D\u5DE5\u4F5C\u533A")),
          (0, import_react.createElement)("input", { className: "sla-input", value: draft.autoSessionWorkspace ?? "", onChange: (e) => set("autoSessionWorkspace", String(e.target.value ?? "")), placeholder: "D:\\workspace\\dsh_plugin" }),
          // Warn while typing rather than after saving: the host rejects a
          // relative `cwd`, and the fallback is silently "host default", so
          // an operator who typed `logs` must be told it will not be used.
          String(draft.autoSessionWorkspace ?? "").trim() && !isAbsolutePath(draft.autoSessionWorkspace) ? (0, import_react.createElement)("div", { className: "sla-note" }, `\u300C${String(draft.autoSessionWorkspace).trim()}\u300D\u4E0D\u662F\u7EDD\u5BF9\u8DEF\u5F84\uFF0C\u4FDD\u5B58\u540E\u4F1A\u6539\u7528\u5BBF\u4E3B\u5F53\u524D\u5DE5\u4F5C\u533A`) : null
        ) : null,
        draft.autoSessionEnabled !== false ? (0, import_react.createElement)(
          "div",
          { className: "sla-field" },
          (0, import_react.createElement)("label", null, "\u521B\u5EFA\u4F1A\u8BDD\u63D0\u793A\u8BCD", (0, import_react.createElement)("i", null, "\u53EA\u66FF\u6362\u9996\u884C\u6307\u4EE4\uFF1B\u544A\u8B66 id\u3001\u8BBE\u5907\u540D\u4E0E\u539F\u59CB\u65E5\u5FD7\u7531\u63D2\u4EF6\u8FFD\u52A0\u3002\u53EF\u7528 {id} \u4E0E {device}")),
          (0, import_react.createElement)("textarea", {
            className: "sla-input sla-textarea",
            rows: 3,
            value: draft.autoSessionPrompt ?? "",
            onChange: (e) => set("autoSessionPrompt", String(e.target.value ?? "")),
            placeholder: "\u5206\u6790\u8FD9\u6761\u65E5\u5FD7"
          }),
          String(draft.autoSessionPrompt ?? "").trim() === "" ? (0, import_react.createElement)("div", { className: "sla-note" }, `\u7559\u7A7A\u5373\u4F7F\u7528\u9ED8\u8BA4\u6307\u4EE4\u300C${AUTO_SESSION_PROMPT}\u300D`) : null
        ) : null
      ),
      (0, import_react.createElement)(
        "div",
        { className: "sla-modal-foot" },
        (0, import_react.createElement)("button", { className: "sla-btn primary", disabled: busy, onClick: () => void save() }, busy ? "\u4FDD\u5B58\u4E2D\u2026" : "\u4FDD\u5B58"),
        (0, import_react.createElement)("button", { className: "sla-btn", onClick: props.onClose }, "\u53D6\u6D88")
      )
    )
  );
}
function AlertCenterPage() {
  injectStyles();
  const [tab, setTab] = (0, import_react.useState)("alerts");
  const [alerts, setAlerts] = (0, import_react.useState)([]);
  const [total, setTotal] = (0, import_react.useState)(0);
  const [filters, setFilters] = (0, import_react.useState)(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = (0, import_react.useState)(null);
  const [detail, setDetail] = (0, import_react.useState)(null);
  const [status, setStatus] = (0, import_react.useState)(null);
  const [stats, setStats] = (0, import_react.useState)(null);
  const [devices, setDevices] = (0, import_react.useState)([]);
  const [error, setError] = (0, import_react.useState)(null);
  const [tokenMsg, setTokenMsg] = (0, import_react.useState)(null);
  const [tokenInput, setTokenInput] = (0, import_react.useState)("");
  const [busy, setBusy] = (0, import_react.useState)(false);
  const [showSettings, setShowSettings] = (0, import_react.useState)(false);
  const [editable, setEditable] = (0, import_react.useState)({});
  const [testMsg, setTestMsg] = (0, import_react.useState)({ message: "<13>Oct  7 10:12:33 SW1 LINK-3: Interface GE1/0/1 link status changed to DOWN" });
  (0, import_react.useEffect)(() => {
    tokenNotice = setTokenMsg;
    return () => {
      tokenNotice = null;
    };
  }, []);
  const query = (0, import_react.useMemo)(() => {
    const p = new URLSearchParams();
    if (filters.severityMax < 7) p.set("severityMax", String(filters.severityMax));
    if (filters.deviceId) p.set("deviceId", filters.deviceId);
    if (filters.stage) p.set("stage", filters.stage);
    if (filters.search) p.set("q", filters.search);
    if (filters.sinceMinutes > 0) p.set("since", String(filters.sinceMinutes * 6e4));
    p.set("limit", "200");
    return p.toString();
  }, [filters]);
  const refresh = (0, import_react.useCallback)(async () => {
    try {
      const j = await api(`/alerts?${query}`);
      setAlerts(j.alerts ?? []);
      setTotal(j.total ?? 0);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, [query]);
  (0, import_react.useEffect)(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 15e3);
    return () => clearInterval(t);
  }, [refresh]);
  (0, import_react.useEffect)(() => {
    const load = async () => {
      try {
        const j = await api("/status");
        setStatus(j.listener);
        setStats(j.stats);
        setEditable(j.config);
        setDevices(j.devices ?? []);
      } catch (e) {
        setError(e.message);
      }
    };
    void load();
    const t = setInterval(() => void load(), 1e4);
    return () => clearInterval(t);
  }, []);
  (0, import_react.useEffect)(() => {
    let es = null;
    let closed = false;
    const connect = async () => {
      const token = await bootstrapToken();
      const url = `${API}/alerts/stream?token=${encodeURIComponent(token)}`;
      es = new EventSource(url);
      const onMsg = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (!data.alert) return;
          setAlerts((prev) => mergeAlert(prev, data.alert));
          setSelectedId((cur) => cur === data.alert.id ? data.alert.id : cur);
        } catch {
        }
      };
      es.addEventListener("alert", onMsg);
      es.addEventListener("update", onMsg);
      es.onerror = () => {
      };
    };
    void connect();
    return () => {
      closed = true;
      void closed;
      es?.close();
    };
  }, []);
  (0, import_react.useEffect)(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let live = true;
    api(`/alerts/${encodeURIComponent(selectedId)}`).then((j) => {
      if (live) setDetail(j.alert);
    }).catch(() => {
      if (live) setDetail(null);
    });
    return () => {
      live = false;
    };
  }, [selectedId]);
  const ack = async () => {
    if (!selectedId) return;
    await api(`/alerts/${encodeURIComponent(selectedId)}/ack`, { method: "POST" });
    void refresh();
  };
  const saveSettings = async (s2) => {
    await api("/settings", { method: "PUT", body: s2 });
    const j = await api("/status");
    setStatus(j.listener);
    setStats(j.stats);
    setEditable(j.config);
  };
  const injectTest = async () => {
    await api("/test-alert", { method: "POST", body: testMsg });
    void refresh();
  };
  const controlListener = async (action) => {
    setBusy(true);
    setError(null);
    try {
      const j = await api("/listener", { method: "POST", body: { action } });
      if (j.status) setStatus(j.status);
      if (j.error) setError(j.error);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const s = stats;
  return (0, import_react.createElement)(
    "div",
    { className: "sla-root" },
    (0, import_react.createElement)(
      "div",
      { className: "sla-seg" },
      (0, import_react.createElement)("button", { className: tab === "alerts" ? "on" : "", onClick: () => setTab("alerts") }, `\u544A\u8B66${total ? ` (${total})` : ""}`),
      (0, import_react.createElement)("button", { className: tab === "selftest" ? "on" : "", onClick: () => setTab("selftest") }, "\u81EA\u68C0"),
      (0, import_react.createElement)("button", { className: tab === "stats" ? "on" : "", onClick: () => setTab("stats") }, "\u8FD0\u884C\u72B6\u6001"),
      (0, import_react.createElement)("span", { style: { flex: 1 } }),
      (0, import_react.createElement)("button", { className: "sla-btn plain", onClick: () => setShowSettings(true) }, "\u8BBE\u7F6E")
    ),
    tokenMsg ? (0, import_react.createElement)(
      "div",
      { className: "sla-msg err" },
      (0, import_react.createElement)("code", null, tokenMsg),
      (0, import_react.createElement)(
        "div",
        { className: "sla-acts" },
        (0, import_react.createElement)("input", { className: "sla-input", style: { flex: 1 }, placeholder: "\u7C98\u8D34\u4EE4\u724C", value: tokenInput, onChange: (e) => setTokenInput(e.target.value) }),
        (0, import_react.createElement)("button", { className: "sla-btn primary", onClick: () => {
          try {
            localStorage.setItem(TOKEN_KEY, tokenInput.trim());
          } catch {
          }
          manualToken = tokenInput.trim();
          tokenProbed = false;
          setTokenMsg(null);
          location.reload();
        } }, "\u4FDD\u5B58\u5E76\u91CD\u8BD5")
      )
    ) : null,
    error ? (0, import_react.createElement)("div", { className: "sla-msg err" }, error) : null,
    tab === "alerts" ? (0, import_react.createElement)(
      "div",
      { className: "sla-body" },
      (0, import_react.createElement)(
        "div",
        { className: "sla-pane list" },
        (0, import_react.createElement)(
          "div",
          { className: "sla-filters" },
          (0, import_react.createElement)("input", { className: "sla-input", placeholder: "\u641C\u7D22\u65E5\u5FD7/\u6807\u7B7E/\u8BBE\u5907", value: filters.search, onChange: (e) => setFilters((f) => ({ ...f, search: e.target.value })) }),
          (0, import_react.createElement)(
            "select",
            { className: "sla-input", value: filters.severityMax, onChange: (e) => setFilters((f) => ({ ...f, severityMax: Number(e.target.value) })) },
            [7, 6, 5, 4, 3, 2, 1, 0].map((n) => (0, import_react.createElement)("option", { key: n, value: n }, n === 7 ? "\u5168\u90E8\u7EA7\u522B" : `\u2264 ${n} ${SEVERITY_LABELS[n] ?? ""}`))
          ),
          (0, import_react.createElement)(
            "select",
            { className: "sla-input", value: filters.stage, onChange: (e) => setFilters((f) => ({ ...f, stage: e.target.value })) },
            (0, import_react.createElement)("option", { value: "" }, "\u5168\u90E8\u9636\u6BB5"),
            Object.entries(STAGE_LABELS).map(([k, v]) => (0, import_react.createElement)("option", { key: k, value: k }, v))
          ),
          (0, import_react.createElement)(
            "select",
            { className: "sla-input", value: filters.deviceId, onChange: (e) => setFilters((f) => ({ ...f, deviceId: e.target.value })) },
            (0, import_react.createElement)("option", { value: "" }, "\u5168\u90E8\u8BBE\u5907"),
            devices.map((d) => (0, import_react.createElement)("option", { key: d.id, value: d.id }, d.name ?? d.ip ?? d.id))
          ),
          (0, import_react.createElement)(
            "select",
            { className: "sla-input", value: filters.sinceMinutes, onChange: (e) => setFilters((f) => ({ ...f, sinceMinutes: Number(e.target.value) })) },
            (0, import_react.createElement)("option", { value: 0 }, "\u5168\u90E8\u65F6\u95F4"),
            (0, import_react.createElement)("option", { value: 15 }, "\u8FD1 15 \u5206\u949F"),
            (0, import_react.createElement)("option", { value: 60 }, "\u8FD1 1 \u5C0F\u65F6"),
            (0, import_react.createElement)("option", { value: 1440 }, "\u8FD1 24 \u5C0F\u65F6")
          )
        ),
        (0, import_react.createElement)(AlertListHead),
        (0, import_react.createElement)(
          "div",
          { className: "sla-rows" },
          alerts.length === 0 ? (0, import_react.createElement)(
            "div",
            { className: "sla-empty" },
            (0, import_react.createElement)("b", null, "\u6CA1\u6709\u544A\u8B66"),
            (0, import_react.createElement)(
              "div",
              { style: { marginTop: 4 } },
              status?.listening ? `\u76D1\u542C\u8FD0\u884C\u4E2D\uFF0C\u5DF2\u6536 ${status.packets} \u4E2A\u5305\u3002\u53BB\u300C\u81EA\u68C0\u300D\u9875\u6CE8\u5165\u4E00\u6761\u6D4B\u8BD5\u65E5\u5FD7\u9A8C\u8BC1\u94FE\u8DEF\u3002` : "\u76D1\u542C\u672A\u8FD0\u884C\uFF0C\u53BB\u300C\u8FD0\u884C\u72B6\u6001\u300D\u9875\u770B\u7ED1\u5B9A\u5931\u8D25\u539F\u56E0\u3002"
            )
          ) : alerts.map((a) => (0, import_react.createElement)(AlertRow, { key: a.id, alert: a, selected: a.id === selectedId, onSelect: () => setSelectedId(a.id) }))
        )
      )
    ) : tab === "selftest" ? (0, import_react.createElement)(
      "div",
      { className: "sla-body" },
      (0, import_react.createElement)(
        "div",
        { className: "sla-pane single" },
        (0, import_react.createElement)(
          "div",
          { className: "sla-test" },
          (0, import_react.createElement)("div", { className: "sla-note" }, "\u628A\u4E0B\u9762\u8FD9\u6761\u5F53\u4F5C\u4ECE\u8BBE\u5907\u53D1\u6765\u7684\u62A5\u6587\u6CE8\u5165\uFF0C\u8D70\u5B8C\u6574\u94FE\u8DEF\uFF08\u89E3\u6790\u2192\u6620\u5C04\u2192\u9884\u8FC7\u6EE4\u2192\u5206\u6790\u2192\u5F53\u65E5\u4F1A\u8BDD\uFF09\u3002\u6CE8\u5165\u540E\u56DE\u300C\u544A\u8B66\u300D\u9875\u770B\u5B83\u3002"),
          (0, import_react.createElement)(
            "div",
            { className: "sla-test-row" },
            (0, import_react.createElement)("input", { className: "sla-input", value: testMsg.message ?? "", onChange: (e) => setTestMsg((t) => ({ ...t, message: e.target.value })) }),
            (0, import_react.createElement)("input", { className: "sla-input", style: { width: 130 }, placeholder: "\u6765\u6E90 IP", value: testMsg.sourceIp ?? "", onChange: (e) => setTestMsg((t) => ({ ...t, sourceIp: e.target.value })) }),
            (0, import_react.createElement)("button", { className: "sla-btn primary", onClick: () => void injectTest() }, "\u6CE8\u5165")
          )
        ),
        status ? (0, import_react.createElement)(
          "div",
          { className: `sla-msg ${status.listening ? "ok" : "err"}` },
          status.listening ? `\u76D1\u542C\u8FD0\u884C\u4E2D \xB7 ${status.transports.join(" + ") || "?"} \xB7 \u7AEF\u53E3 ${status.boundPorts.join(", ") || "\u65E0"} \xB7 \u5DF2\u6536 ${status.packets} \u5305` : "\u76D1\u542C\u672A\u8FD0\u884C\uFF1A\u81EA\u68C0\u6CE8\u5165\u4E0D\u4F9D\u8D56\u6536\u5305\u7AEF\u53E3\uFF0C\u4F46\u771F\u5B9E\u8BBE\u5907\u65E5\u5FD7\u8FDB\u4E0D\u6765\u3002"
        ) : null,
        (0, import_react.createElement)("div", { className: "sla-note" }, "\u6765\u6E90 IP \u7559\u7A7A\u65F6\u7528\u672C\u673A\u56DE\u73AF\u5730\u5740\uFF0C\u56E0\u6B64\u80FD\u5426\u547D\u4E2D\u8BBE\u5907\u6620\u5C04\u53D6\u51B3\u4E8E\u6709\u6CA1\u6709\u628A 127.0.0.1 \u914D\u8FDB\u8BBE\u5907\u5217\u8868\u3002")
      )
    ) : (0, import_react.createElement)(
      "div",
      { className: "sla-body" },
      (0, import_react.createElement)(
        "div",
        { className: "sla-pane single" },
        status ? (0, import_react.createElement)(
          "div",
          null,
          (0, import_react.createElement)(
            "div",
            { className: `sla-msg ${status.listening ? "ok" : "err"}` },
            status.listening ? `\u76D1\u542C\u8FD0\u884C\u4E2D \xB7 ${status.transports.join(" + ") || "?"} \xB7 \u7AEF\u53E3 ${status.boundPorts.join(", ") || "\u65E0"} \xB7 \u5DF2\u6536 ${status.packets} \u5305` : "\u76D1\u542C\u672A\u8FD0\u884C"
          ),
          (0, import_react.createElement)(
            "div",
            { style: { marginTop: 8 } },
            (0, import_react.createElement)("button", { className: "sla-btn", disabled: busy || !status.listening, onClick: () => void controlListener("stop") }, busy ? "\u5904\u7406\u4E2D\u2026" : "\u505C\u6B62 syslog \u63A5\u6536"),
            status.listening ? null : (0, import_react.createElement)("button", { className: "sla-btn primary", style: { marginLeft: 8 }, disabled: busy, onClick: () => void controlListener("start") }, "\u542F\u52A8 syslog \u63A5\u6536"),
            (0, import_react.createElement)("div", { className: "sla-note", style: { marginTop: 6 } }, "\u505C\u6B62\u53EA\u5173\u6389\u6536\u5305\u5957\u63A5\u5B57\uFF1A\u9762\u677F\u3001\u5DE5\u5177\u3001\u5DF2\u5B58\u544A\u8B66\u90FD\u8FD8\u5728\uFF0C\u968F\u65F6\u53EF\u518D\u542F\u52A8\u3002")
          ),
          status.failedPorts.length ? (0, import_react.createElement)(
            "div",
            { className: "sla-msg err" },
            "\u7ED1\u5B9A\u5931\u8D25\uFF1A",
            status.failedPorts.map((f) => `${f.port} \u2192 ${f.reason}`).join("\uFF1B"),
            (0, import_react.createElement)("div", { className: "sla-note" }, "Linux \u4E0A 514 \u5C5E\u4E8E\u7279\u6743\u7AEF\u53E3\uFF0C\u9700\u63D0\u6743\u6216 setcap\uFF1B\u53EF\u6539\u7528 1514 \u5E76\u5728\u8BBE\u5907\u4FA7\u540C\u6B65\u6539 syslog server \u7AEF\u53E3\u3002")
          ) : null,
          status.listening && status.packets === 0 ? (0, import_react.createElement)("div", { className: "sla-msg warn" }, "\u76D1\u542C\u5DF2\u542F\u52A8\u4F46\u4E00\u4E2A\u5305\u90FD\u6CA1\u6536\u5230\uFF1A\u68C0\u67E5\u8BBE\u5907\u4FA7 syslog server \u5730\u5740/\u7AEF\u53E3\uFF0C\u4EE5\u53CA\u672C\u673A\u9632\u706B\u5899\u662F\u5426\u653E\u884C\u5165\u7AD9\u3002") : null
        ) : (0, import_react.createElement)("div", { className: "sla-loading" }, "\u8FDE\u63A5\u5BBF\u4E3B\u2026"),
        s ? (0, import_react.createElement)(
          "div",
          { className: "sla-stats" },
          (0, import_react.createElement)("h4", null, "\u8BA1\u6570"),
          (0, import_react.createElement)(
            "div",
            { className: "sla-kv" },
            (0, import_react.createElement)("span", null, "\u6536\u5305"),
            (0, import_react.createElement)("b", null, String(s.received)),
            (0, import_react.createElement)("span", null, "\u5EFA\u7ACB\u544A\u8B66"),
            (0, import_react.createElement)("b", null, String(s.alertsCreated)),
            (0, import_react.createElement)("span", null, "\u9884\u8FC7\u6EE4\u4E22\u5F03"),
            (0, import_react.createElement)("b", null, String(s.filtered)),
            (0, import_react.createElement)("span", null, "\u53BB\u91CD"),
            (0, import_react.createElement)("b", null, String(s.deduped)),
            (0, import_react.createElement)("span", null, "\u9650\u6D41"),
            (0, import_react.createElement)("b", null, String(s.rateLimited)),
            (0, import_react.createElement)("span", null, "\u98CE\u66B4\u805A\u5408"),
            (0, import_react.createElement)("b", null, String(s.storms))
          ),
          (0, import_react.createElement)("h4", null, "\u8BBE\u5907\u6620\u5C04\u6765\u6E90"),
          devices.length === 0 ? (0, import_react.createElement)("div", { className: "sla-note" }, "hillstone \u672A\u8FD4\u56DE\u8BBE\u5907\u5217\u8868\uFF0C\u6765\u6E90 IP \u65E0\u6CD5\u6620\u5C04\u5230\u8BBE\u5907\uFF0C\u544A\u8B66\u4F1A\u6309\u300C\u672A\u6620\u5C04\u7B56\u7565\u300D\u5904\u7406\u3002") : (0, import_react.createElement)("div", { className: "sla-note" }, `\u5171 ${devices.length} \u53F0\u8BBE\u5907\uFF0C\u6309\u8BBE\u5907 IP \u7CBE\u786E\u5339\u914D syslog \u6765\u6E90\u3002\u8BBE\u5907 syslog \u6E90\u5730\u5740\u4E0E\u7BA1\u7406\u5730\u5740\u4E0D\u540C\u65F6\u9700\u8981\u989D\u5916\u6620\u5C04\u89C4\u5219\uFF08\u5F53\u524D\u7248\u672C\u6309 IP \u5339\u914D\uFF09\u3002`)
        ) : null
      )
    ),
    showSettings ? (0, import_react.createElement)(Settings, { settings: editable, onSave: saveSettings, onClose: () => setShowSettings(false) }) : null,
    // The detail is a modal now, so "selected" means "the modal is open":
    // closing it clears the selection rather than leaving a row highlighted
    // with nothing shown.
    detail ? (0, import_react.createElement)(AlertModal, {
      alert: detail,
      onAck: () => void ack(),
      onClose: () => {
        setDetail(null);
        setSelectedId(null);
      }
    }) : null
  );
}
var IconComponent = () => (0, import_react.createElement)(
  "svg",
  { viewBox: "0 0 24 24", width: 18, height: 18, "aria-hidden": true, style: { display: "block" } },
  (0, import_react.createElement)("path", { fill: "currentColor", opacity: 0.9, d: "M12 2 2 20h20L12 2zm0 4 6.8 12H5.2L12 6z" }),
  (0, import_react.createElement)("circle", { cx: 12, cy: 15, r: 1.4, fill: "currentColor" })
);
var name = "dsh-syslog-alert-client";
var inject = ["slots", "sidebarRightTabs", "sidebarRight", "uiWorkspace"];
var TAB_KIND = PANEL_ID;
function apply(ctx) {
  try {
    const unwatch = ctx.inject(["sidebarRightTabs", "sidebarRight"], () => {
      try {
        ctx.sidebarRightTabs.register({
          id: TAB_KIND,
          kind: TAB_KIND,
          priority: "extension",
          title: () => "\u667A\u80FD\u544A\u8B66\u4E2D\u5FC3",
          guide: [
            {
              order: 30,
              title: () => "\u667A\u80FD\u544A\u8B66\u4E2D\u5FC3",
              description: () => "\u63A5\u6536\u7F51\u7EDC\u8BBE\u5907\u53D1\u6765\u7684 syslog \u544A\u8B66\uFF1A\u89E3\u6790\u3001\u53BB\u91CD\u3001\u9650\u6D41\u4E0E\u98CE\u66B4\u805A\u5408\u540E\u8FDB\u5165\u5B9E\u65F6\u544A\u8B66\u6D41\u3002\u5F53\u5929\u7B2C\u4E00\u6761\u65E5\u5FD7\u65B0\u5EFA\u666E\u901A\u4F1A\u8BDD\u4EA4\u7ED9 agent \u5206\u6790\uFF0C\u7ED3\u8BBA\u7531 agent \u8C03\u7528 syslog_conclude \u5199\u56DE\u8BE6\u60C5\u3002\u5217\u8868\u70B9\u51FB\u884C\u770B\u5B8C\u6574\u65F6\u95F4\u7EBF\u3002",
              icon: IconComponent
            }
          ]
        });
        ctx.slots.inject(
          "sidebar.right.pane.tab",
          () => ctx.slots.register({ name: "sidebar.right.pane.tab", key: TAB_KIND, inject: () => ({ api: ctx }) }, AlertCenterPage)
        );
      } catch (error) {
        console.error("[dsh-syslog-alert] right tab registration failed:", error);
      }
    });
    void unwatch;
  } catch (error) {
    console.error("[dsh-syslog-alert] client failed to load:", error);
  }
}
var CSS = `
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
   line up vertically. Tabular numerals alone are not enough \u2014 the width has to
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
`;
return module.exports; } });
//# sourceMappingURL=client.js.map
