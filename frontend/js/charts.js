// Chart.js helpers in the app style: thin marks, subdued grid, at most 3 series.
import { locale, t } from "./i18n.js";
import { COLORS, SERIES, el } from "./util.js";

const registry = new WeakMap();
const nf1 = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });

function base(unit) {
  const Chart = window.Chart;
  Chart.defaults.font.family = '"Roboto Mono", ui-monospace, monospace';
  Chart.defaults.font.size = 10.5;
  Chart.defaults.color = COLORS.text2;
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: "nearest", intersect: false },
    plugins: {
      legend: { display: false, labels: { boxWidth: 10, boxHeight: 10, color: COLORS.text2 } },
      tooltip: {
        backgroundColor: "#0c0c0c",
        borderColor: "rgba(220, 38, 38, 0.45)",
        borderWidth: 1,
        titleColor: COLORS.text,
        bodyColor: COLORS.text,
        callbacks: {
          label: (ctx) => {
            const v = ctx.parsed.x !== undefined && ctx.chart.options.indexAxis === "y" ? ctx.parsed.x : ctx.parsed.y;
            return `${ctx.dataset.label ? ctx.dataset.label + ": " : ""}${nf1.format(v)}${unit ? " " + unit : ""}`;
          },
        },
      },
    },
  };
}

function grid() {
  return { color: "rgba(255, 255, 255, 0.06)", drawTicks: false };
}

export function destroy(canvas) {
  const c = registry.get(canvas);
  if (c) c.destroy();
  registry.delete(canvas);
}

/** Horizontal bars for rankings. spec: {labels, series:[{name, values}], unit} */
export function barChart(canvas, spec) {
  destroy(canvas);
  const series = spec.series.slice(0, 3);
  const opts = base(spec.unit);
  const vertical = Boolean(spec.vertical);
  opts.indexAxis = vertical ? "x" : "y";
  opts.plugins.legend.display = series.length > 1;
  const valueAxis = { beginAtZero: true, grid: grid(), border: { display: false }, ticks: { maxTicksLimit: 5, callback: (v) => nf1.format(v) } };
  const catAxis = { grid: { display: false }, border: { display: false }, ticks: vertical ? { maxTicksLimit: 8, maxRotation: 0, autoSkip: true } : {} };
  opts.scales = vertical ? { x: catAxis, y: valueAxis } : { x: valueAxis, y: catAxis };
  const chart = new window.Chart(canvas, {
    type: "bar",
    data: {
      labels: spec.labels,
      datasets: series.map((s, i) => ({
        label: s.name,
        data: s.values,
        backgroundColor: SERIES[i],
        borderRadius: 4,
        borderSkipped: "start",
        barPercentage: vertical ? 0.9 : 0.72,
        categoryPercentage: 0.82,
      })),
    },
    options: opts,
  });
  registry.set(canvas, chart);
  return chart;
}

/** Time series. spec: {labels, series:[{name, values}], unit, timeLabels?: bool} */
export function lineChart(canvas, spec) {
  destroy(canvas);
  const series = spec.series.slice(0, 3);
  const opts = base(spec.unit);
  opts.plugins.legend.display = series.length > 1;
  opts.plugins.legend.position = "top";
  opts.plugins.legend.align = "start";
  opts.interaction = { mode: "index", intersect: false };
  opts.scales = {
    x: { grid: { display: false }, border: { color: COLORS.rule }, ticks: { maxTicksLimit: 7, autoSkip: true, maxRotation: 0 } },
    y: { beginAtZero: true, grid: grid(), border: { display: false }, ticks: { maxTicksLimit: 5, callback: (v) => nf1.format(v) } },
  };
  const chart = new window.Chart(canvas, {
    type: "line",
    data: {
      labels: spec.labels,
      datasets: series.map((s, i) => ({
        label: s.name,
        data: s.values,
        borderColor: SERIES[i],
        backgroundColor: SERIES[i],
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.25,
        spanGaps: spec.spanGaps ?? true,
      })),
    },
    options: opts,
  });
  registry.set(canvas, chart);
  return chart;
}

/** Value table as an alternative to the chart */
export function valueTable(spec) {
  const series = spec.series.slice(0, 3);
  const head = el("tr", {}, el("th", {}, ""), series.map((s) => el("th", {}, s.name)));
  const rows = spec.labels.map((l, i) =>
    el("tr", {}, el("td", {}, l), series.map((s) => el("td", {}, `${nf1.format(s.values[i])}${spec.unit ? " " + spec.unit : ""}`))),
  );
  return el("details", {}, el("summary", {}, t("chart.table")), el("table", {}, el("thead", {}, head), el("tbody", {}, rows)));
}
