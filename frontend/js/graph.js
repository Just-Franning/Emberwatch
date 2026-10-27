// Link graph of a people search case (SVG, black and white). Shapes name the kind of a node, lines the evidence:
//   circle    search subject (large, filled) and accounts (filled: found; dashed outline: unsure)
//   square    names, persons, organisations, e-mail addresses, phone numbers
//   diamond   places, websites, domains, notes
//   solid line: confirmed (account found, profile statement, link or proof); dashed: hint; thick: mutual link
//   arrow: one account links to (or is proven by) another; small ring in a node: added by hand.
// Layout: nodes with a stored position stay where they are; the others are placed by a force simulation (computed at
// once, no animation). Dragging a node moves only that node and its lines (onMove stores it), dragging the background
// pans, the wheel or +/- zooms. Selecting a node dims everything that is not connected to it.
// Node objects may carry subject: true (set by the caller for the searched user name or e-mail address).
import { t } from "./i18n.js";
import { countryName, el } from "./util.js";

const NS = "http://www.w3.org/2000/svg";
const SQUARE = new Set(["name", "person", "org", "phone", "email"]);
const ARROW = new Set(["links_to", "verified", "registered", "local_part"]);
const R = { subject: 15, account: 9, other: 7 };
const round1 = (v) => Math.round(v * 10) / 10;

const svg = (tag, attrs = {}) => {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined && v !== false) n.setAttribute(k, String(v));
  return n;
};

/** Display text of a node (countries by name, long values shortened). */
export function nodeLabel(n, max = 30) {
  if (n.kind === "location") return countryName(n.label);
  const s = String(n.label || "");
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function shape(n) {
  if (n.kind === "account") return "account";
  if (n.kind === "username" || (n.kind === "email" && n.subject)) return "subject";
  return SQUARE.has(n.kind) ? "square" : "diamond";
}

/** Places nodes without a stored position (force simulation; fixed nodes do not move). Returns id -> {x, y, fixed}. */
export function layout(nodes, edges, { width = 800, height = 600, all = false } = {}) {
  const pos = new Map();
  const free = [];
  const cx = width / 2, cy = height / 2;
  for (const n of nodes) {
    if (!all && Number.isFinite(n.x) && Number.isFinite(n.y)) pos.set(n.id, { x: n.x, y: n.y, fixed: true });
    else free.push(n);
  }
  if (!free.length) return pos;
  const nb = new Map(nodes.map((n) => [n.id, []]));
  for (const e of edges) {
    if (nb.has(e.src) && nb.has(e.dst)) { nb.get(e.src).push(e.dst); nb.get(e.dst).push(e.src); }
  }
  free.forEach((n, i) => { // start next to placed neighbours, else on a spiral around the centre
    const placed = nb.get(n.id).map((id) => pos.get(id)).filter(Boolean);
    const a = i * 2.399963, r = 40 + 14 * Math.sqrt(i);
    if (placed.length) {
      const mx = placed.reduce((s, p) => s + p.x, 0) / placed.length, my = placed.reduce((s, p) => s + p.y, 0) / placed.length;
      pos.set(n.id, { x: mx + 60 * Math.cos(a), y: my + 60 * Math.sin(a), fixed: false });
    } else {
      pos.set(n.id, { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a), fixed: false });
    }
  });
  const ids = nodes.map((n) => n.id);
  const pts = ids.map((id) => pos.get(id));
  const k = Math.max(70, Math.min(140, Math.sqrt((width * height) / Math.max(ids.length, 1))));
  const far = 9 * k * k;
  // fewer steps for large graphs and when only a few nodes are new (the rest is fixed)
  const iters = ids.length > 900 ? 40 : ids.length > 400 ? 110 : free.length < ids.length / 4 ? 140 : 320;
  const dx = new Float64Array(ids.length), dy = new Float64Array(ids.length);
  const index = new Map(ids.map((id, i) => [id, i]));
  const springs = edges.map((e) => [index.get(e.src), index.get(e.dst)]).filter(([a, b]) => a !== undefined && b !== undefined && a !== b);
  let temp = width / 8;
  for (let it = 0; it < iters; it++) {
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < pts.length; i++) { // repulsion
      const a = pts[i];
      for (let j = i + 1; j < pts.length; j++) {
        const b = pts[j];
        let ex = a.x - b.x, ey = a.y - b.y;
        let d2 = ex * ex + ey * ey;
        if (d2 > far) continue;
        if (d2 < 0.01) { ex = (i % 7) - 2.5; ey = (j % 5) - 1.5; d2 = ex * ex + ey * ey; } // same spot: push apart
        const f = (k * k) / d2;
        dx[i] += ex * f; dy[i] += ey * f; dx[j] -= ex * f; dy[j] -= ey * f;
      }
    }
    for (const [i, j] of springs) { // attraction along the lines
      const a = pts[i], b = pts[j];
      const ex = a.x - b.x, ey = a.y - b.y;
      const f = Math.sqrt(ex * ex + ey * ey) / k;
      dx[i] -= ex * f; dy[i] -= ey * f; dx[j] += ex * f; dy[j] += ey * f;
    }
    for (let i = 0; i < pts.length; i++) { // gravity and cooling; fixed nodes stay
      const p = pts[i];
      if (p.fixed) continue;
      const vx = dx[i] + (cx - p.x) * 0.02, vy = dy[i] + (cy - p.y) * 0.02;
      const len = Math.sqrt(vx * vx + vy * vy) || 1;
      p.x += (vx / len) * Math.min(len, temp);
      p.y += (vy / len) * Math.min(len, temp);
    }
    temp *= 0.985;
  }
  return pos;
}

export class Graph {
  constructor(container, { onSelect, onConnect, onMove }) {
    this.onSelect = onSelect; // (node | edge | null, "node" | "edge" | null) => void
    this.onConnect = onConnect; // (srcNode, dstNode) => void
    this.onMove = onMove; // ([[id, x, y], ...]) => void
    this.mode = "select";
    this.view = { x: 0, y: 0, k: 1 };
    this.data = { nodes: [], edges: [] };
    this.byId = new Map();
    this.nodeEls = new Map();
    this.edgeEls = new Map();
    this.incident = new Map();
    this.sel = null;
    this.from = null;
    this.fitted = false;
    this.svg = svg("svg", { class: "graph-svg", role: "group", tabindex: 0, "aria-label": t("os.graph_aria") });
    const defs = svg("defs");
    const arrow = svg("marker", { id: "g-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    arrow.append(svg("path", { d: "M0,0 L10,5 L0,10 z", class: "g-arrow" }));
    defs.append(arrow);
    this.root = svg("g");
    this.svg.append(defs, this.root);
    container.append(this.svg);
    this._bind();
  }

  setMode(mode) {
    this.mode = mode === "connect" ? "connect" : "select";
    this.from = null;
    this.svg.classList.toggle("connecting", this.mode === "connect");
    this._paintSel();
  }

  size() {
    const r = this.svg.getBoundingClientRect();
    return { width: Math.max(320, r.width), height: Math.max(240, r.height) };
  }

  /** New data; nodes without a position are placed. Returns the positions that were computed (to be stored). */
  set(data, { all = false, fit = false } = {}) {
    this.data = { nodes: data.nodes || [], edges: data.edges || [] };
    const { width, height } = this.size();
    const placed = layout(this.data.nodes, this.data.edges, { width, height, all });
    const fresh = [];
    for (const n of this.data.nodes) {
      const p = placed.get(n.id);
      if (p && !p.fixed) { n.x = round1(p.x); n.y = round1(p.y); fresh.push([n.id, n.x, n.y]); }
    }
    this.byId = new Map(this.data.nodes.map((n) => [n.id, n]));
    this.incident = new Map(this.data.nodes.map((n) => [n.id, []]));
    for (const e of this.data.edges) {
      this.incident.get(e.src)?.push(e);
      this.incident.get(e.dst)?.push(e);
    }
    if (this.sel && !this.find(this.sel)) this.sel = null;
    if (this.from && !this.byId.has(this.from)) this.from = null;
    this.render();
    if (!this.fitted || all || fit) { this.fit(); this.fitted = true; }
    return fresh;
  }

  find(sel) {
    if (!sel) return null;
    return sel.type === "node" ? this.byId.get(sel.id) : this.data.edges.find((e) => e.id === sel.id);
  }

  select(type, id) {
    this.sel = type && id ? { type, id } : null;
    this._paintSel();
  }

  _radius(n) {
    const sh = shape(n);
    return sh === "subject" ? R.subject : sh === "account" ? R.account : R.other;
  }

  _placeEdge(e) {
    const els = this.edgeEls.get(e.id);
    const a = this.byId.get(e.src), b = this.byId.get(e.dst);
    if (!els || !a || !b) return;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const ra = this._radius(a), rb = this._radius(b) + (els.arrow ? 3 : 0);
    const set = (n, x1, y1, x2, y2) => { n.setAttribute("x1", x1); n.setAttribute("y1", y1); n.setAttribute("x2", x2); n.setAttribute("y2", y2); };
    set(els.line, round1(a.x + (dx / d) * ra), round1(a.y + (dy / d) * ra), round1(b.x - (dx / d) * rb), round1(b.y - (dy / d) * rb));
    set(els.hit, round1(a.x), round1(a.y), round1(b.x), round1(b.y));
    if (els.label) { els.label.setAttribute("x", round1((a.x + b.x) / 2)); els.label.setAttribute("y", round1((a.y + b.y) / 2 - 4)); }
  }

  _moveNode(n) {
    this.nodeEls.get(n.id)?.setAttribute("transform", `translate(${round1(n.x)},${round1(n.y)})`);
    for (const e of this.incident.get(n.id) || []) this._placeEdge(e);
  }

  render() {
    const edgesG = svg("g", { class: "g-edges" });
    const nodesG = svg("g", { class: "g-nodes" });
    this.nodeEls.clear();
    this.edgeEls.clear();
    for (const e of this.data.edges) {
      if (!this.byId.has(e.src) || !this.byId.has(e.dst)) continue;
      const arrow = ARROW.has(e.kind) && !e.mutual;
      const cls = ["g-edge", e.strength === "hint" ? "hint" : "confirmed", e.mutual ? "mutual" : null, e.manual ? "manual" : null].filter(Boolean).join(" ");
      const line = svg("line", { class: cls, "marker-end": arrow ? "url(#g-arrow)" : null, "data-edge": e.id });
      const hit = svg("line", { class: "g-hit", "data-edge": e.id });
      const title = svg("title");
      title.textContent = [t(`os.ek.${e.kind}`), t(`os.str.${e.strength}`), e.mutual ? t("os.lg.mutual") : null, e.kind === "manual" ? e.label : null]
        .filter(Boolean).join(" · ");
      hit.append(title);
      let label = null;
      if (e.kind === "manual" && e.label) { // labels of drawn lines are the analyst's words; automatic ones are in the title
        label = svg("text", { class: "g-elabel", "text-anchor": "middle" });
        label.textContent = e.label.length > 24 ? `${e.label.slice(0, 23)}…` : e.label;
      }
      edgesG.append(line, hit, ...(label ? [label] : []));
      this.edgeEls.set(e.id, { line, hit, label, arrow });
      this._placeEdge(e);
    }
    for (const n of this.data.nodes) {
      const sh = shape(n);
      const unsure = n.kind === "account" && n.data?.status === "unsure";
      const g = svg("g", { class: `g-node s-${sh}${n.manual ? " manual" : ""}${unsure ? " unsure" : ""}`, "data-node": n.id });
      const r = this._radius(n);
      if (sh === "subject" || sh === "account") g.append(svg("circle", { class: "g-shape", r }));
      else if (sh === "square") g.append(svg("rect", { class: "g-shape", x: -r, y: -r, width: 2 * r, height: 2 * r }));
      else g.append(svg("rect", { class: "g-shape", x: -r * 0.85, y: -r * 0.85, width: 1.7 * r, height: 1.7 * r, transform: "rotate(45)" }));
      if (n.manual) g.append(svg("circle", { class: "g-mark", r: 2.4 }));
      const label = svg("text", { class: "g-label", x: r + 5, y: 4 });
      label.textContent = nodeLabel(n);
      const title = svg("title");
      title.textContent = `${t(`os.nk.${n.kind}`)}: ${n.kind === "location" ? countryName(n.label) : n.label}`;
      g.append(label, title);
      nodesG.append(g);
      this.nodeEls.set(n.id, g);
      this._moveNode(n);
    }
    this.root.replaceChildren(edgesG, nodesG);
    this._applyView();
    this._paintSel();
  }

  _paintSel() {
    for (const x of this.root.querySelectorAll(".sel, .from, .nb")) x.classList.remove("sel", "from", "nb");
    const s = this.sel ? this.find(this.sel) : null;
    if (s && this.sel.type === "node") {
      this.nodeEls.get(s.id)?.classList.add("sel");
      for (const e of this.incident.get(s.id) || []) {
        this.edgeEls.get(e.id)?.line.classList.add("nb");
        this.nodeEls.get(e.src === s.id ? e.dst : e.src)?.classList.add("nb");
      }
    } else if (s) {
      this.edgeEls.get(s.id)?.line.classList.add("sel");
      for (const id of [s.src, s.dst]) this.nodeEls.get(id)?.classList.add("nb");
    }
    this.root.classList.toggle("focus", Boolean(s));
    if (this.from) this.nodeEls.get(this.from)?.classList.add("from");
    this._announce(s);
  }

  /** Screen readers: the selection is announced through the label of the canvas. */
  _announce(s) {
    if (!s) { this.svg.setAttribute("aria-label", t("os.graph_aria")); return; }
    const text = this.sel.type === "node" ? `${t(`os.nk.${s.kind}`)}: ${nodeLabel(s, 80)} · ${t("os.g.links_n", { n: (this.incident.get(s.id) || []).length })}`
      : `${t(`os.ek.${s.kind}`)}: ${nodeLabel(this.byId.get(s.src) || {}, 40)} – ${nodeLabel(this.byId.get(s.dst) || {}, 40)}`;
    this.svg.setAttribute("aria-label", `${t("os.graph_aria")} · ${text}`);
  }

  _applyView() {
    this.root.setAttribute("transform", `translate(${round1(this.view.x)},${round1(this.view.y)}) scale(${this.view.k})`);
    this.svg.style.setProperty("--k", String(this.view.k)); // labels keep their size on screen (styles.css)
    this.svg.classList.toggle("far", this.view.k < 0.55); // zoomed far out: only the important labels
  }

  zoom(f, at = null) {
    const { width, height } = this.size();
    const px = at ? at.x : width / 2, py = at ? at.y : height / 2;
    const k = Math.min(4, Math.max(0.12, this.view.k * f));
    this.view.x = px - ((px - this.view.x) * k) / this.view.k;
    this.view.y = py - ((py - this.view.y) * k) / this.view.k;
    this.view.k = k;
    this._applyView();
  }

  fit() {
    const ns = this.data.nodes;
    if (!ns.length) { this.view = { x: 0, y: 0, k: 1 }; this._applyView(); return; }
    const { width, height } = this.size();
    const xs = ns.map((n) => n.x), ys = ns.map((n) => n.y);
    const minX = Math.min(...xs) - 30, maxX = Math.max(...xs) + 150, minY = Math.min(...ys) - 30, maxY = Math.max(...ys) + 30;
    // a large graph is not shrunk below readability: it is centred and can be panned
    const k = Math.min(1.4, Math.max(0.45, Math.min(width / (maxX - minX || 1), height / (maxY - minY || 1))));
    this.view = { k, x: (width - (maxX - minX) * k) / 2 - minX * k, y: (height - (maxY - minY) * k) / 2 - minY * k };
    this._applyView();
  }

  /** Centres the view on one node and selects it (from the lists outside the graph and the arrow keys). */
  reveal(id) {
    const n = this.byId.get(id);
    if (!n) return false;
    const { width, height } = this.size();
    if (this.view.k < 0.8) this.view.k = 1; // a node to look at is shown close enough to read its neighbours
    this.view.x = width / 2 - n.x * this.view.k;
    this.view.y = height / 2 - n.y * this.view.k;
    this._applyView();
    this.select("node", id);
    return true;
  }

  /** Lays out every node again (stored positions included) and returns the new positions. */
  relayout() {
    return this.set(this.data, { all: true });
  }

  _point(ev) {
    const r = this.svg.getBoundingClientRect();
    return { x: ev.clientX - r.left, y: ev.clientY - r.top };
  }

  _click(target) {
    const nodeEl = target?.closest?.("[data-node]");
    const edgeEl = target?.closest?.("[data-edge]");
    if (nodeEl) {
      const n = this.byId.get(Number(nodeEl.dataset.node));
      if (!n) return;
      if (this.mode === "connect") {
        if (!this.from) { this.from = n.id; this._paintSel(); return; }
        const src = this.byId.get(this.from);
        this.from = null;
        this._paintSel();
        if (src && src.id !== n.id) this.onConnect(src, n);
        return;
      }
      this.select("node", n.id);
      this.onSelect(n, "node");
    } else if (edgeEl) {
      const e = this.data.edges.find((x) => x.id === Number(edgeEl.dataset.edge));
      if (!e) return;
      this.select("edge", e.id);
      this.onSelect(e, "edge");
    } else {
      this.from = null;
      this.select(null);
      this.onSelect(null, null);
    }
  }

  /** Keyboard: arrows step through the nodes, Enter acts on the selected one (connect mode), +/- zoom, 0 fits,
   * Esc leaves the connect mode and the selection. */
  _key(ev) {
    const ns = this.data.nodes;
    if (ev.key === "+" || ev.key === "=") { this.zoom(1.2); ev.preventDefault(); return; }
    if (ev.key === "-") { this.zoom(1 / 1.2); ev.preventDefault(); return; }
    if (ev.key === "0") { this.fit(); ev.preventDefault(); return; }
    if (ev.key === "Escape") { this.setMode("select"); this.select(null); this.onSelect(null, null); ev.stopPropagation(); return; }
    if (!ns.length) return;
    if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(ev.key)) {
      const cur = this.sel?.type === "node" ? ns.findIndex((n) => n.id === this.sel.id) : -1;
      const step = ev.key === "ArrowRight" || ev.key === "ArrowDown" ? 1 : -1;
      const next = ns[(cur + step + ns.length) % ns.length];
      this.reveal(next.id);
      this.onSelect(next, "node");
      ev.preventDefault();
    } else if (ev.key === "Enter" && this.sel?.type === "node" && this.mode === "connect") {
      this._click(this.nodeEls.get(this.sel.id));
      ev.preventDefault();
    }
  }

  _bind() {
    let drag = null;
    this.svg.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      const nodeEl = ev.target.closest("[data-node]");
      const node = nodeEl ? this.byId.get(Number(nodeEl.dataset.node)) : null;
      drag = { start: this._point(ev), moved: false, target: ev.target, node, view: { ...this.view }, id: ev.pointerId };
      if (node) drag.origin = { x: node.x, y: node.y };
      this.svg.setPointerCapture(ev.pointerId);
    });
    this.svg.addEventListener("pointermove", (ev) => {
      if (!drag || ev.pointerId !== drag.id) return;
      const p = this._point(ev);
      const dx = p.x - drag.start.x, dy = p.y - drag.start.y;
      if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
      drag.moved = true;
      if (drag.node && this.mode === "select") {
        drag.node.x = drag.origin.x + dx / this.view.k;
        drag.node.y = drag.origin.y + dy / this.view.k;
        this._moveNode(drag.node);
      } else if (!drag.node) {
        this.view.x = drag.view.x + dx;
        this.view.y = drag.view.y + dy;
        this._applyView();
      }
    });
    const end = (ev) => {
      if (!drag || ev.pointerId !== drag.id) return;
      const d = drag;
      drag = null;
      try { this.svg.releasePointerCapture(ev.pointerId); } catch { /* already released */ }
      if (!d.moved) this._click(d.target);
      else if (d.node && this.mode === "select") this.onMove([[d.node.id, round1(d.node.x), round1(d.node.y)]]);
    };
    this.svg.addEventListener("pointerup", end);
    this.svg.addEventListener("pointercancel", (ev) => {
      if (!drag || ev.pointerId !== drag.id) return;
      if (drag.node && drag.origin) { drag.node.x = drag.origin.x; drag.node.y = drag.origin.y; this._moveNode(drag.node); }
      drag = null;
    });
    this.svg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      this.zoom(ev.deltaY < 0 ? 1.15 : 1 / 1.15, this._point(ev));
    }, { passive: false });
    this.svg.addEventListener("keydown", (ev) => this._key(ev));
  }
}

/** Legend of the graph (shapes and lines). */
export function graphLegend() {
  const item = (cls, label) => el("span", { class: "gl-item" }, el("i", { class: `gl ${cls}`, "aria-hidden": "true" }), label);
  return el("div", { class: "graph-legend" },
    item("subject", t("os.lg.subject")), item("account", t("os.lg.account")), item("account unsure", t("os.lg.unsure")),
    item("square", t("os.lg.square")), item("diamond", t("os.lg.diamond")),
    item("line", t("os.str.confirmed")), item("line hint", t("os.str.hint")), item("line mutual", t("os.lg.mutual")),
    item("mark", t("os.lg.manual")));
}
