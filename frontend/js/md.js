// Minimal, safe Markdown renderer for AI text.
// Supports: "### " headings, "- "/"* " lists, **bold**, paragraphs.
// Creates DOM nodes with text content only: no HTML from the model ever reaches the page.

import { t } from "./i18n.js";
import { el } from "./util.js";

function inline(text) {
  const frag = document.createDocumentFragment();
  const parts = String(text).split("**");
  parts.forEach((part, i) => {
    if (!part) return;
    // odd indices lie between ** … ** (only for a closed pair)
    const bold = i % 2 === 1 && i < parts.length - 1;
    frag.append(bold ? el("strong", {}, part) : document.createTextNode(i % 2 === 1 ? `**${part}` : part));
  });
  return frag;
}

export function renderMarkdown(src) {
  const root = el("div", { class: "md" });
  let list = null;
  let para = [];
  const flushPara = () => {
    if (para.length) root.append(el("p", {}, inline(para.join(" "))));
    para = [];
  };
  for (const raw of String(src || "").split(/\r?\n/)) {
    const line = raw.trim();
    const li = line.match(/^[-*]\s+(.*)$/);
    const h = line.match(/^#{1,6}\s+(.*)$/);
    if (li) {
      flushPara();
      if (!list) { list = el("ul"); root.append(list); }
      list.append(el("li", {}, inline(li[1])));
      continue;
    }
    list = null;
    if (h) { flushPara(); root.append(el("h4", {}, inline(h[1]))); continue; }
    if (!line) { flushPara(); continue; }
    para.push(line);
  }
  flushPara();
  return root;
}

export function toPlainText(report) {
  const lines = [report.title || "", ""];
  lines.push(String(report.summary || "").replace(/\*\*/g, ""));
  if (report.findings?.length) {
    lines.push("", `${t("ai.findings")}:`);
    for (const f of report.findings) lines.push(`- [${f.severity}] ${f.title}: ${f.detail}`);
  }
  if (report.recommendations?.length) {
    lines.push("", `${t("ai.recommendations")}:`);
    for (const r of report.recommendations) lines.push(`- ${r}`);
  }
  if (report.caveats?.length) {
    lines.push("", `${t("ai.caveats")}:`);
    for (const c of report.caveats) lines.push(`- ${c}`);
  }
  lines.push("", t("ai.plain_footer", { model: report.model, t: report.generated_at }));
  return lines.join("\n");
}

export function toMarkdown(report, thread = []) {
  const out = [`# ${report.title || t("ai.analysis")}`, "",
    `_${t("ai.md_meta", { model: report.model || "Gemini", t: report.generated_at || "", q: report.question ? t("ai.md_q", { q: report.question }) : "" })}_`, "",
    String(report.summary || "").trim(), ""];
  if (report.findings?.length) {
    out.push(`## ${t("ai.findings")}`, "");
    for (const f of report.findings) out.push(`- **${t(`sev.${f.severity}`)}:** ${f.title}. ${f.detail}`);
    out.push("");
  }
  for (const c of report.charts || []) {
    out.push(`### ${c.title}${c.unit ? ` (${c.unit})` : ""}`, "", `| | ${c.series.map((s) => s.name).join(" | ")} |`,
      `|---|${c.series.map(() => "---:").join("|")}|`);
    c.labels.forEach((l, i) => out.push(`| ${l} | ${c.series.map((s) => s.values[i]).join(" | ")} |`));
    out.push("");
  }
  if (report.recommendations?.length) {
    out.push(`## ${t("ai.recommendations")}`, "", ...report.recommendations.map((r) => `- ${r}`), "");
  }
  if (report.caveats?.length) {
    out.push(`## ${t("ai.caveats")}`, "", ...report.caveats.map((c) => `- ${c}`), "");
  }
  for (const th of thread) {
    out.push(`## ${t("ai.followup_q", { q: th.question })}`, "", String(th.answer || "").trim(), "");
  }
  out.push("---", t("ai.md_sources"));
  return out.join("\n");
}
