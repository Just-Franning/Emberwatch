// Runs tools and recipes on the server and reads the NDJSON event stream:
//   start | row | info | progress | step | step_result  (live)   ->   result | error  (final)
import { t } from "./i18n.js";

async function errorOf(r) {
  let msg = "";
  let key = "";
  try {
    const j = await r.json();
    msg = typeof j.detail === "string" ? j.detail : "";
    key = j.key || "";
  } catch { /* ignore */ }
  if (r.status === 401 && key === "err.auth_required") window.location.assign("login");
  const e = new Error(msg || `HTTP ${r.status}`);
  e.status = r.status;
  e.key = key;
  return e;
}

async function* ndjson(path, body, signal) {
  const r = await fetch(path, {
    method: "POST", signal,
    headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw await errorOf(r);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) yield JSON.parse(line);
    }
  }
  if (buf.trim()) yield JSON.parse(buf);
}

/**
 * One run of a tool or recipe. handlers: {onEvent(ev), onResult(result), onError(message)}.
 * Returns a handle with stop(). The final callback is always exactly one of onResult / onError
 * (onError(null) when stopped by the user).
 */
export function startRun({ tool = null, recipe = null, target = "", params = {}, consent = false }, handlers) {
  const ctl = new AbortController();
  let finished = false;
  const finish = (fn, arg) => {
    if (finished) return;
    finished = true;
    fn?.(arg);
  };
  (async () => {
    try {
      const path = recipe ? "api/tb/recipe" : "api/tb/run";
      const body = recipe ? { recipe, target } : { tool, target, params, consent };
      for await (const ev of ndjson(path, body, ctl.signal)) {
        if (ev.type === "result") return finish(handlers.onResult, ev.result);
        if (ev.type === "error") return finish(handlers.onError, ev.text || t("common.error", { msg: ev.key || "?" }));
        handlers.onEvent?.(ev);
      }
      finish(handlers.onError, t("tb.stream_lost"));
    } catch (e) {
      if (e.name === "AbortError") finish(handlers.onError, null);
      else finish(handlers.onError, e.message || String(e));
    }
  })();
  return {
    stop() { ctl.abort(); },
    get done() { return finished; },
  };
}
