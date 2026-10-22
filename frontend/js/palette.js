// Command palette (Ctrl+K): jump to any area or view, open objects, start tools and recipes for an input.
// "ping 8.8.8.8" style input uses the tool aliases from the registry.
import { t } from "./i18n.js";
import { detect, loadRegistry, objectOf } from "./registry.js";
import { go, routes } from "./router.js";
import { el, kids } from "./util.js";

const NAV = [
  ["lage", "pal.nav.lage"], ["welt", "pal.nav.welt"], ["analyse", "pal.nav.analyse"], [routes.tools(), "pal.nav.tools"], ["analyse/history", "pal.nav.history"],
  [routes.view("kev"), "an.view.kev"], [routes.view("infra"), "an.view.infra"], [routes.view("c2"), "an.view.c2"], [routes.view("ransom"), "an.view.ransom"], [routes.view("platforms"), "an.view.platforms"],
  ["netz", "pal.nav.netz"], ["netz/assets", "nz.nav.assets"], ["netz/products", "nz.nav.products"], ["netz/alerts", "nz.nav.alerts"],
  ["netz/logs", "nz.nav.logs"], ["netz/myip", "nz.nav.myip"],
];

export class Palette {
  constructor({ onTool }) {
    this.onTool = onTool; // (toolId, target) => void
    this.items = [];
    this.idx = 0;
    this.seq = 0;
    this.input = el("input", { type: "text", spellcheck: "false", maxlength: 4096, placeholder: t("pal.ph"), "aria-label": t("pal.ph"),
      role: "combobox", "aria-expanded": "true", "aria-controls": "pal-list", "aria-autocomplete": "list" });
    this.list = el("ol", { class: "pal-list", id: "pal-list", role: "listbox" });
    this.box = el("div", { class: "palette", role: "dialog", "aria-modal": "true", "aria-label": t("pal.title") },
      this.input, this.list, el("p", { class: "note" }, t("pal.hint")));
    this.back = el("div", { class: "palette-back", hidden: true }, this.box);
    document.body.append(this.back);
    this.back.addEventListener("mousedown", (e) => { if (e.target === this.back) this.close(); });
    this.input.addEventListener("input", () => this.update());
    this.input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { this.move(1); e.preventDefault(); }
      else if (e.key === "ArrowUp") { this.move(-1); e.preventDefault(); }
      else if (e.key === "Enter") { this.exec(this.items[this.idx]); e.preventDefault(); }
      else if (e.key === "Escape") { this.close(); e.preventDefault(); }
    });
  }

  get isOpen() { return !this.back.hidden; }

  open(prefill = "") {
    this.back.hidden = false;
    this.input.value = prefill;
    this.update();
    this.input.focus();
    this.input.select();
  }

  close() { this.back.hidden = true; }

  toggle() { if (this.isOpen) this.close(); else this.open(); }

  move(d) {
    if (!this.items.length) return;
    this.idx = (this.idx + d + this.items.length) % this.items.length;
    this.draw();
  }

  exec(item) {
    if (!item) return;
    this.close();
    item.run();
  }

  async update() {
    const seq = ++this.seq;
    const q = this.input.value.trim();
    const ql = q.toLowerCase();
    const nav = NAV.map(([path, key]) => ({ label: t(key), kind: t("pal.k.go"), run: () => go(path) }))
      .filter((x) => !ql || x.label.toLowerCase().includes(ql));
    this.items = nav;
    this.idx = 0;
    this.draw();
    if (!q) return;
    let reg = null;
    try { reg = await loadRegistry(); } catch { reg = null; }
    const dyn = [];
    // "<alias> <target>"
    const m = q.match(/^(\S+)\s+(.+)$/s);
    if (reg && m) {
      const tool = reg.tools.find((x) => x.aliases.includes(m[1].toLowerCase()));
      if (tool && !tool.client_only) dyn.push({ label: `${tool.name}: ${m[2].trim().slice(0, 80)}`, kind: t("pal.k.tool"), run: () => this.onTool(tool.id, m[2].trim()) });
    }
    let det = null;
    try { det = await detect(q.slice(0, 4096)); } catch { det = null; }
    if (seq !== this.seq) return;
    const o = objectOf(det);
    if (o) dyn.push({ label: `${t(`obj.type.${o.type}`)}: ${o.value}`, kind: t("pal.k.object"), run: () => go(routes.obj(o.type, o.value)) });
    if (reg && det && det.type !== "empty") {
      const target = det.type === "mailhdr" ? q : det.value;
      for (const r of det.recipes || []) {
        const rec = reg.recipes.find((x) => x.id === r);
        if (rec && det.type !== "mailhdr") dyn.push({ label: `${rec.name}: ${target.slice(0, 80)}`, kind: t("pal.k.recipe"), run: () => go(routes.tools(target, null, false, r)) });
      }
      for (const id of det.tools || []) {
        const tool = reg.byId[id];
        if (!tool || tool.client_only || id === "mailhdr") continue;
        dyn.push({ label: `${tool.name}: ${target.slice(0, 80)}`, kind: t("pal.k.tool"), run: () => this.onTool(id, target) });
      }
    }
    if (det?.type === "text") {
      for (const ty of ["actor", "malware", "group", "vendor"]) dyn.push({ label: `${t(`obj.type.${ty}`)}: ${q.slice(0, 80)}`, kind: t("pal.k.object"), run: () => go(routes.obj(ty, q.slice(0, 200))) });
    }
    this.items = [...dyn, ...nav];
    this.idx = 0;
    this.draw();
  }

  draw() {
    kids(this.list, ...this.items.slice(0, 40).map((x, i) => el("li", {
      role: "option", "aria-selected": String(i === this.idx), class: i === this.idx ? "on" : null,
      onmousedown: (e) => { e.preventDefault(); this.exec(x); },
    }, el("span", { class: "pal-kind" }, x.kind), el("span", {}, x.label))));
    this.list.querySelector(".on")?.scrollIntoView({ block: "nearest" });
  }
}
