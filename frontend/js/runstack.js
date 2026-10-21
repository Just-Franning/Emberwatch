// A stack of tool and recipe runs (newest first) as used on object pages and in the tool box.
// Each card shows live progress while the run streams and the rendered result afterwards.
import { t } from "./i18n.js";
import { loadRegistry } from "./registry.js";
import { destroyIn, renderResult } from "./result.js";
import { go, routes } from "./router.js";
import { startRun } from "./runner.js";
import { el, kids, num, sevTag } from "./util.js";

function liveLine(ev) {
  if (ev.type === "info") return ev.text;
  if (ev.type === "progress") return t("mt.progress", { done: num(ev.done), total: num(ev.total) });
  if (ev.type === "start") return t("rs.start", { ip: ev.ip || "?" });
  if (ev.type === "row") {
    if (ev.kind === "reply") return t("rs.reply", { seq: ev.seq, rtt: ev.rtt });
    if (ev.kind === "timeout") return t("rs.timeout", { seq: ev.seq });
    if (ev.kind === "hop") {
      const v = ev.loss !== undefined && ev.loss !== null ? `${ev.loss} % · ${ev.avg ?? "–"} ms` : ev.rtt !== null && ev.rtt !== undefined ? `${ev.rtt} ms` : "";
      return `${ev.n}  ${ev.ip || "*"}  ${v}`.trim();
    }
  }
  return null;
}

export class RunStack {
  constructor({ onMap }) {
    this.onMap = onMap;
    this.node = el("div", { class: "runstack" });
    this.runs = new Set();
  }

  stopAll() {
    for (const r of this.runs) r.stop();
    this.runs.clear();
  }

  clear() {
    this.stopAll();
    destroyIn(this.node);
    kids(this.node);
  }

  card(title, target) {
    const live = el("ol", { class: "live-log", "aria-live": "polite" }, el("li", { class: "state" }, t("common.running")));
    const out = el("div");
    const stop = el("button", { type: "button", class: "small" }, t("common.stop"));
    const close = el("button", { type: "button", class: "small", title: t("common.close") }, "×");
    const box = el("div", { class: "runcard" },
      el("div", { class: "runcard-head" }, el("strong", {}, title), target ? el("span", { class: "mono muted" }, target) : null,
        el("span", { class: "spacer" }), stop, close),
      live, out);
    this.node.prepend(box);
    box.scrollIntoView({ block: "nearest" });
    return { box, live, out, stop, close };
  }

  async tool(toolId, target, params = {}, consent = false) {
    const reg = await loadRegistry();
    const tool = reg.byId[toolId];
    const c = this.card(tool?.name || toolId, target);
    const lines = [];
    const run = startRun({ tool: toolId, target, params, consent }, {
      onEvent: (ev) => {
        const line = liveLine(ev);
        if (!line) return;
        lines.push(line);
        kids(c.live, ...lines.slice(-12).map((x) => el("li", {}, x)));
      },
      onResult: (r) => this.finish(c, run, r, toolId, target),
      onError: (msg) => this.fail(c, run, msg),
    });
    this.wire(c, run);
  }

  recipe(recipeId, target, title) {
    const c = this.card(title, target.length > 120 ? `${target.slice(0, 120)} …` : target);
    const steps = new Map();
    const draw = () => kids(c.live, ...[...steps.values()].map((s) => el("li", {},
      s.done ? (s.error ? el("span", { class: "sev medium" }, t("res.step_failed")) : sevTag(s.sev)) : el("span", { class: "sev info" }, t("rs.running")),
      s.title, s.error ? el("span", { class: "muted" }, ` · ${s.error}`) : null)));
    const run = startRun({ recipe: recipeId, target }, {
      onEvent: (ev) => {
        if (ev.type === "step") steps.set(ev.tool, { title: ev.title, done: false });
        else if (ev.type === "step_result") {
          const s = steps.get(ev.tool) || { title: ev.tool };
          steps.set(ev.tool, { ...s, done: true, sev: ev.result?.verdict?.sev || "info", error: ev.error });
        } else return;
        draw();
      },
      onResult: (r) => this.finish(c, run, r),
      onError: (msg) => this.fail(c, run, msg),
    });
    this.wire(c, run);
  }

  wire(c, run) {
    this.runs.add(run);
    c.stop.addEventListener("click", () => run.stop());
    c.close.addEventListener("click", () => { run.stop(); this.runs.delete(run); destroyIn(c.box); c.box.remove(); });
  }

  finish(c, run, r, toolId = null, target = null) {
    this.runs.delete(run);
    c.stop.remove();
    c.live.remove();
    c.box.classList.add("done"); // the result has its own heading
    const actions = toolId ? [el("button", { type: "button", onclick: () => go(routes.tools(target, toolId)) }, t("rs.options"))] : [];
    kids(c.out, renderResult(r, { onMap: this.onMap, actions }));
  }

  fail(c, run, msg) {
    this.runs.delete(run);
    c.stop.remove();
    kids(c.live, el("li", { class: "state err" }, msg === null ? t("mt.stopped") : msg));
  }
}
