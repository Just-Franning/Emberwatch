// Gemini: start analyses, show the report with text/charts, follow-up questions, export (Markdown, print/PDF), history.
import { barChart, destroy, lineChart, valueTable } from "./charts.js";
import { t } from "./i18n.js";
import { renderMarkdown, toMarkdown, toPlainText } from "./md.js";
import { api, countryName, dateTime, download, el, kids, reduceMotion, sevTag } from "./util.js";

function charts(list) {
  return (list || []).map((c) => {
    const canvas = el("canvas", { role: "img", "aria-label": c.title });
    requestAnimationFrame(() => (c.type === "line" ? lineChart(canvas, c) : barChart(canvas, c)));
    return el("figure", {}, el("h5", { style: "margin:0 0 4px" }, c.title), el("div", { class: "chart-box" }, canvas), valueTable(c));
  });
}

export class AIPanel {
  constructor() {
    this.out = document.getElementById("ai-out");
    this.history = document.getElementById("ai-history");
    this.countryBtn = document.getElementById("ai-country");
    this.regionBtn = document.getElementById("ai-region");
    this.country = null;
    this.busy = false;
    this.current = null;
    this.thread = [];

    document.querySelectorAll("#sect-ai .ai-actions button[data-scope]").forEach((b) =>
      b.addEventListener("click", () => this.run({ scope: b.dataset.scope, country: b.dataset.scope === "country" ? this.country : null })));
    document.getElementById("ai-ask").addEventListener("submit", (e) => {
      e.preventDefault();
      const q = document.getElementById("ai-question").value.trim();
      if (q) this.run({ scope: "question", question: q, country: this.country });
    });
    this.history.addEventListener("click", (e) => e.stopPropagation()); // do not toggle <summary>
    this.history.addEventListener("change", async () => {
      const r = this.reports?.find((x) => String(x.id) === this.history.value);
      if (r) await this.show(r, true);
    });
    this.loadHistory();
  }

  setRegion(region) {
    const on = Boolean(region?.codes?.length);
    this.regionBtn.hidden = !on;
    if (on) {
      this.regionBtn.textContent = t("ai.region", { name: region.name });
      this.regionBtn.title = t("ai.region_title", { codes: region.codes.join(", ") });
    }
  }

  setCountry(cc) {
    this.country = cc;
    this.countryBtn.disabled = !cc;
    this.countryBtn.textContent = cc ? t("ai.country_named", { name: countryName(cc) }) : t("ai.country");
  }

  async loadHistory() {
    try { this.reports = (await api("api/ai/reports?limit=40")).filter((r) => !String(r.scope || "").startsWith("obj:")); } catch { this.reports = []; }
    kids(this.history,
      el("option", { value: "" }, this.reports.length ? t("ai.history") : t("ai.history_none")),
      ...this.reports.map((r) => el("option", { value: r.id }, `${dateTime(r.created_at)} ${r.scope === "daily" ? t("ai.daily") : ""} ${r.title || r.scope}`.replace(/\s+/g, " "))),
    );
  }

  setBusy(on) {
    this.busy = on;
    document.querySelectorAll("#sect-ai button").forEach((b) => (b.disabled = on));
    if (!on) this.countryBtn.disabled = !this.country;
  }

  async run(body) {
    if (this.busy) return;
    document.getElementById("sect-ai").open = true;
    this.setBusy(true);
    this.out.querySelectorAll("canvas").forEach(destroy);
    kids(this.out, el("p", { class: "state" }, t("ai.running")));
    this.out.scrollIntoView({ block: "nearest", behavior: reduceMotion ? "auto" : "smooth" });
    try {
      const r = await api("api/ai/analyze", { json: body });
      await this.show(r, true);
      this.out.scrollIntoView({ block: "start", behavior: reduceMotion ? "auto" : "smooth" });
      if (!r.cached) this.loadHistory();
    } catch (e) {
      kids(this.out, el("p", { class: "state err" }, t("ai.failed", { msg: e.message })));
    } finally {
      this.setBusy(false);
    }
  }

  async show(r, loadThread) {
    this.current = r;
    this.thread = [];
    if (loadThread && r.id) {
      try { this.thread = await api(`api/ai/reports/${r.id}/thread`); } catch { this.thread = []; }
    }
    this.render();
  }

  render() {
    if (!this.current) return;
    this.out.querySelectorAll("canvas").forEach(destroy);
    kids(this.out, reportArticle(this.current, this.thread, { onFollowup: (form) => this.followup(form) }));
  }

  async followup(form) {
    const input = form.querySelector("input");
    const q = input.value.trim();
    if (!q || this.busy || !this.current?.id) return;
    this.setBusy(true);
    form.querySelector("button").disabled = true;
    const wait = el("p", { class: "state" }, t("ai.followup_running"));
    form.before(wait);
    try {
      const a = await api("api/ai/followup", { json: { report_id: this.current.id, question: q } });
      this.thread.push(a);
      this.render();
    } catch (e) {
      wait.className = "state err";
      wait.textContent = t("ai.followup_failed", { msg: e.message });
    } finally {
      this.setBusy(false);
    }
  }

  print() { printReport(this.current, this.thread); }
}

/** Report article (Gemini analysis) with copy/Markdown/print actions, findings, charts and the follow-up thread. */
export function reportArticle(r, thread, { onFollowup }) {
  const copy = el("button", { type: "button" }, t("ai.copy"));
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(toPlainText(r)); copy.textContent = t("ai.copied"); } catch { copy.textContent = t("ai.copy_failed"); }
    setTimeout(() => (copy.textContent = t("ai.copy")), 2000);
  });
  const md = el("button", { type: "button", onclick: () => download(`${t("ai.file")}-${(r.generated_at || "").slice(0, 10)}.md`, toMarkdown(r, thread), "text/markdown;charset=utf-8") }, t("ai.markdown"));
  const pdf = el("button", { type: "button", onclick: () => printReport(r, thread) }, t("ai.print"));
  const followForm = el("form", { class: "followup" },
    el("label", { class: "sr-only" }, t("ai.followup_label")),
    el("input", { type: "text", maxlength: 600, placeholder: t("ai.followup_ph"), "aria-label": t("ai.followup_label") }),
    el("button", { type: "submit", disabled: !r.id }, t("ai.send")));
  followForm.addEventListener("submit", (e) => { e.preventDefault(); onFollowup?.(followForm); });
  return el("article", { class: "report" },
    el("h3", {}, r.title || t("ai.analysis")),
    el("div", { class: "rmeta" }, t("ai.meta", { q: r.question ? t("ai.meta_q", { q: r.question }) : "", model: r.model, t: dateTime(r.generated_at),
      cached: r.cached ? t("ai.meta_cached") : "" })),
    el("div", { class: "ractions" }, copy, md, pdf),
    renderMarkdown(r.summary),
    r.findings?.length ? el("h5", {}, t("ai.findings")) : null,
    r.findings?.length ? el("ul", { class: "findings" }, r.findings.map((f) =>
      el("li", {}, sevTag(f.severity), el("strong", {}, f.title), el("div", { class: "fdetail" }, f.detail)))) : null,
    ...charts(r.charts),
    r.recommendations?.length ? el("h5", {}, t("ai.recommendations")) : null,
    r.recommendations?.length ? el("ul", { class: "plain" }, r.recommendations.map((x) => el("li", {}, x))) : null,
    r.caveats?.length ? el("h5", {}, t("ai.caveats")) : null,
    r.caveats?.length ? el("ul", { class: "plain caveats" }, r.caveats.map((x) => el("li", {}, x))) : null,
    el("p", { class: "aiflag" }, t("ai.flag")),
    el("div", { class: "thread" },
      ...thread.flatMap((th) => [el("div", { class: "q" }, t("ai.followup_q", { q: th.question })), renderMarkdown(th.answer), ...charts(th.charts)]),
      r.id ? followForm : el("p", { class: "note" }, t("ai.followup_na"))));
}

export function printReport(r, thread) {
  const area = document.getElementById("print-area");
  kids(area, ...[
    el("h1", {}, r.title || t("ai.analysis")),
    el("div", { class: "meta" }, t("ai.print_meta", { model: r.model, t: dateTime(r.generated_at) })),
    renderMarkdown(r.summary),
    r.findings?.length ? el("h2", {}, t("ai.findings")) : null,
    r.findings?.length ? el("ul", {}, r.findings.map((f) => el("li", {}, el("strong", {}, `${t(`sev.${f.severity}`)}: ${f.title}. `), f.detail))) : null,
    ...(r.charts || []).flatMap((c) => [el("h2", {}, c.title), valueTable(c)]),
    r.recommendations?.length ? el("h2", {}, t("ai.recommendations")) : null,
    r.recommendations?.length ? el("ul", {}, r.recommendations.map((x) => el("li", {}, x))) : null,
    r.caveats?.length ? el("h2", {}, t("ai.caveats")) : null,
    r.caveats?.length ? el("ul", {}, r.caveats.map((x) => el("li", {}, x))) : null,
    ...thread.flatMap((th) => [el("h2", {}, t("ai.followup_q", { q: th.question })), renderMarkdown(th.answer)]),
  ].filter(Boolean));
  area.querySelectorAll("details").forEach((d) => (d.open = true));
  window.print();
}
