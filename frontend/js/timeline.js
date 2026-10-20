// Timeline: show the map state of a past calendar day (UTC) and play it back.
import { locale, t } from "./i18n.js";
import { api, el } from "./util.js";

export class Timeline {
  constructor({ onDay, onLive }) {
    this.onDay = onDay;
    this.onLive = onLive;
    this.days = [];
    this.live = true;
    this.timer = null;
    this.range = document.getElementById("tl-range");
    this.label = document.getElementById("tl-day");
    this.liveBtn = document.getElementById("tl-live");
    this.playBtn = document.getElementById("tl-play");
    let debounce = null;
    this.range.addEventListener("input", () => {
      this.pause();
      this.showLabel();
      clearTimeout(debounce);
      debounce = setTimeout(() => this.go(Number(this.range.value)), 180);
    });
    this.liveBtn.addEventListener("click", () => this.setLive());
    this.playBtn.addEventListener("click", () => (this.timer ? this.pause() : this.play()));
  }

  liveLabel() {
    return this.days.length ? t("tl.live_days", { n: this.days.length }) : t("tl.live_building");
  }

  async load() {
    try { this.days = await api("api/timeline/days"); } catch { this.days = []; }
    const today = new Date().toISOString().slice(0, 10);
    this.days = this.days.filter((d) => d < today); // today = live
    this.range.max = String(Math.max(0, this.days.length - 1));
    this.range.disabled = !this.days.length;
    this.playBtn.disabled = this.days.length < 2;
    if (this.live) {
      this.range.value = this.range.max;
      this.label.textContent = this.liveLabel();
    }
  }

  static dayLabel(d) {
    return new Date(`${d}T12:00:00Z`).toLocaleDateString(locale, { weekday: "short", day: "2-digit", month: "2-digit", year: "numeric" });
  }

  showLabel() {
    const d = this.days[Number(this.range.value)];
    if (d) this.label.textContent = Timeline.dayLabel(d);
  }

  async go(i) {
    const day = this.days[i];
    if (!day) return;
    this.live = false;
    this.liveBtn.classList.remove("on");
    this.liveBtn.setAttribute("aria-pressed", "false");
    this.showLabel();
    try {
      const data = await api(`api/timeline?day=${day}`);
      if (!data.final) this.label.append(el("span", { class: "tag warn", title: t("tl.preliminary_title") }, t("tl.preliminary")));
      this.onDay(data);
    } catch (e) {
      this.label.textContent = t("common.error", { msg: e.message });
    }
  }

  setLive() {
    this.pause();
    this.live = true;
    this.liveBtn.classList.add("on");
    this.liveBtn.setAttribute("aria-pressed", "true");
    this.range.value = this.range.max;
    this.label.textContent = this.liveLabel();
    this.onLive();
  }

  play() {
    if (this.days.length < 2) return;
    let i = this.live ? 0 : Number(this.range.value);
    if (i >= this.days.length - 1) i = 0;
    this.playBtn.textContent = t("tl.pause");
    const step = async () => {
      this.range.value = String(i);
      await this.go(i);
      i += 1;
      if (i >= this.days.length) { this.pause(); return; }
      this.timer = setTimeout(step, 1400);
    };
    this.timer = setTimeout(step, 0);
  }

  pause() {
    clearTimeout(this.timer);
    this.timer = null;
    this.playBtn.textContent = t("tl.play");
  }
}
