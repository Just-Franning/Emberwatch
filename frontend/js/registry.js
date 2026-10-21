// Tool registry from the server (/api/tb/registry) and the shared building blocks around it:
// flags (passive/active/intrusive, "target sees you", third party), parameter forms, input detection.
import { t } from "./i18n.js";
import { api, el } from "./util.js";

export const GROUPS = ["reach", "identity", "threat", "hardening", "mail", "convert"];
export const LEVELS = ["passive", "active", "intrusive"];

let cache = null;

export async function loadRegistry() {
  if (!cache) {
    cache = api("api/tb/registry").then((r) => ({ ...r, byId: Object.fromEntries(r.tools.map((x) => [x.id, x])) }))
      .catch((e) => { cache = null; throw e; });
  }
  return cache;
}

/** Input detection on the server (same rules as the runs). Returns {type, value, display, tools, recipes, …}. */
export async function detect(q) {
  return api(`api/tb/detect?q=${encodeURIComponent(q)}`);
}

/** Flags of a tool or result: level, whether the target sees the request, which third party receives data. */
export function flags(x, { short = false } = {}) {
  const out = [el("span", { class: `flag lvl-${x.level}`, title: t(`tb.level_title.${x.level}`) }, t(`tb.level.${x.level}`))];
  if (x.target_sees) out.push(el("span", { class: "flag sees", title: t("tb.sees_title") }, t(short ? "tb.sees_short" : "tb.sees")));
  if (x.third_party) out.push(el("span", { class: "flag third", title: t("tb.third_title") }, short ? t("tb.third_short") : t("tb.third", { name: x.third_party })));
  return el("span", { class: "flags" }, out);
}

/** Parameter inputs of a tool. Returns {node, values(), consentNeeded()}. */
export function paramForm(tool, { compact = false } = {}) {
  const inputs = {};
  const parts = [];
  for (const p of tool.params || []) {
    let input;
    if (p.kind === "bool") {
      input = el("input", { type: "checkbox", checked: Boolean(p.default) });
      parts.push(el("label", { class: "pcheck" }, input, p.label));
    } else if (p.kind === "choice") {
      input = el("select", {}, ...p.choices.map((c) => el("option", { value: c, selected: c === p.default }, t(`tb.choice.${c}`) === `tb.choice.${c}` ? c : t(`tb.choice.${c}`))));
      parts.push(el("label", {}, p.label, input));
    } else if (p.kind === "int") {
      input = el("input", { type: "number", value: p.default, min: p.min ?? undefined, max: p.max ?? undefined, step: 1, class: "num-in" });
      parts.push(el("label", {}, p.label, input));
    } else {
      input = el("input", { type: "text", value: p.default ?? "", maxlength: 200, spellcheck: "false" });
      parts.push(el("label", { class: "grow" }, p.label, input));
    }
    inputs[p.name] = { p, input };
  }
  let consent = null;
  if (tool.consent) {
    consent = el("input", { type: "checkbox" });
    const row = el("label", { class: "consent", hidden: true }, consent, t("tb.consent", { name: inputs[tool.consent]?.p.label || tool.consent }));
    const trigger = inputs[tool.consent]?.input;
    trigger?.addEventListener("change", () => { row.hidden = !trigger.checked; });
    parts.push(row);
  }
  return {
    node: parts.length ? el("div", { class: compact ? "params compact" : "params" }, parts) : null,
    values() {
      const out = {};
      for (const [name, { p, input }] of Object.entries(inputs)) {
        if (p.kind === "bool") out[name] = input.checked;
        else if (p.kind === "int") out[name] = input.value === "" ? p.default : Number(input.value);
        else out[name] = input.value.trim();
      }
      return out;
    },
    consent() { return Boolean(consent?.checked); },
    consentMissing() { return Boolean(tool.consent && inputs[tool.consent]?.input.checked && !consent?.checked); },
  };
}

/** CyberChef runs in the browser: link with the input prefilled (base64 without padding, as CyberChef writes it). */
export function cyberChefUrl(base, input) {
  const bytes = new TextEncoder().encode(input || "");
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/=+$/, "");
  return `${base}#input=${encodeURIComponent(b64)}`;
}

/** Object type a detection result opens (URLs and e-mail addresses have their own handling). */
export function objectOf(det) {
  if (!det) return null;
  if (["ip", "cidr", "asn", "domain", "url", "hash", "cve"].includes(det.type)) return { type: det.type, value: det.value };
  if (det.type === "email" && det.domain) return { type: "domain", value: det.domain };
  return null;
}
