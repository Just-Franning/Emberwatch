// Start animation: ember particles, scan sweep, glitch logo and a boot log fed with the real loading steps.
// Classic script (no module) so it runs before the page renders. Skippable with click or any key;
// off when disabled in the settings; static and short with prefers-reduced-motion.
// API for app.js: window.EmberBoot.step(text, state), .progress(fraction), .done()
(function () {
  "use strict";
  var root = document.documentElement;
  var enabled = true;
  try { enabled = localStorage.getItem("emberwatch.boot") !== "off"; } catch (e) { /* ignore */ }
  var noop = { step: function () {}, progress: function () {}, done: function () {}, active: false };
  if (!enabled || !document.querySelector) {
    root.classList.add("no-boot");
    window.EmberBoot = noop;
    return;
  }
  root.classList.add("booting");
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var started = Date.now();
  var MIN_MS = reduced ? 500 : 2200;
  var finished = false;
  var raf = 0;
  var box, canvas, ctx, logList, bar;
  var particles = [];
  var pending = [];

  function lang() {
    var m = document.cookie.match(/(?:^|;\s*)ew_lang=(de|en)(?:;|$)/);
    if (m) return m[1];
    try { var s = localStorage.getItem("emberwatch.lang"); if (s === "de" || s === "en") return s; } catch (e) { /* ignore */ }
    return (navigator.language || "en").toLowerCase().indexOf("de") === 0 ? "de" : "en";
  }
  var TXT = {
    de: { skip: "Klicken oder Taste drücken zum Überspringen", sub: "Cyber-Lagebild" },
    en: { skip: "Click or press any key to skip", sub: "Cyber threat picture" },
  }[lang()];

  function resize() {
    if (!canvas) return;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(window.innerWidth * dpr);
    canvas.height = Math.floor(window.innerHeight * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function spawn(initial) {
    var w = window.innerWidth, h = window.innerHeight;
    return {
      x: Math.random() * w,
      y: initial ? Math.random() * h : h + 10,
      r: 0.6 + Math.random() * 2.2,
      vy: 0.35 + Math.random() * 1.4,
      vx: (Math.random() - 0.5) * 0.4,
      life: 0.4 + Math.random() * 0.6,
      hue: 5 + Math.random() * 30,
      phase: Math.random() * Math.PI * 2,
    };
  }

  function frame(ts) {
    var w = window.innerWidth, h = window.innerHeight;
    ctx.clearRect(0, 0, w, h);
    // faint grid
    ctx.strokeStyle = "rgba(220, 38, 38, 0.06)";
    ctx.lineWidth = 1;
    var step = 48;
    var off = (ts / 60) % step;
    ctx.beginPath();
    for (var x = -step + off; x < w; x += step) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
    for (var y = -step + off; y < h; y += step) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.stroke();
    // scan sweep
    var sy = ((ts / 9) % (h + 200)) - 100;
    var g = ctx.createLinearGradient(0, sy - 80, 0, sy + 4);
    g.addColorStop(0, "rgba(239, 68, 68, 0)");
    g.addColorStop(1, "rgba(239, 68, 68, 0.10)");
    ctx.fillStyle = g;
    ctx.fillRect(0, sy - 80, w, 84);
    // embers
    ctx.globalCompositeOperation = "lighter";
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      p.y -= p.vy;
      p.x += p.vx + Math.sin(ts / 700 + p.phase) * 0.3;
      var flicker = 0.55 + 0.45 * Math.sin(ts / 120 + p.phase * 3);
      var a = Math.max(0, Math.min(1, (p.y / h) * 1.2)) * p.life * flicker;
      ctx.fillStyle = "hsla(" + p.hue + ", 95%, 58%, " + a.toFixed(3) + ")";
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
      if (p.y < -10) particles[i] = spawn(false);
    }
    ctx.globalCompositeOperation = "source-over";
    if (!finished) raf = window.requestAnimationFrame(frame);
  }

  function addLine(text, state) {
    if (!logList) { pending.push([text, state]); return; }
    var li = document.createElement("li");
    li.className = state || "ok";
    var tag = document.createElement("span");
    tag.className = "st";
    tag.textContent = state === "fail" ? "[FAIL]" : state === "warn" ? "[WARN]" : state === "run" ? "[ .. ]" : "[ OK ]";
    var msg = document.createElement("span");
    msg.textContent = " " + text;
    li.appendChild(tag);
    li.appendChild(msg);
    logList.appendChild(li);
    while (logList.children.length > 9) logList.removeChild(logList.firstChild);
  }

  function hide() {
    if (finished) return;
    finished = true;
    window.cancelAnimationFrame(raf);
    root.classList.add("boot-out");
    window.setTimeout(function () {
      root.classList.remove("booting", "boot-out");
      root.classList.add("no-boot");
      if (box && box.parentNode) box.parentNode.removeChild(box);
    }, reduced ? 50 : 650);
    window.removeEventListener("keydown", skip, true);
  }

  function skip() { hide(); }

  function init() {
    box = document.getElementById("boot");
    if (!box) { window.EmberBoot = noop; return; }
    canvas = document.getElementById("boot-canvas");
    logList = document.getElementById("boot-log");
    bar = document.getElementById("boot-bar");
    document.getElementById("boot-skip").textContent = TXT.skip;
    document.getElementById("boot-sub").textContent = TXT.sub;
    box.addEventListener("click", skip);
    window.addEventListener("keydown", skip, true);
    for (var i = 0; i < pending.length; i++) addLine(pending[i][0], pending[i][1]);
    pending = [];
    if (!reduced && canvas && canvas.getContext) {
      ctx = canvas.getContext("2d");
      resize();
      window.addEventListener("resize", resize);
      var n = Math.min(160, Math.round(window.innerWidth * window.innerHeight / 9000));
      for (var k = 0; k < n; k++) particles.push(spawn(true));
      raf = window.requestAnimationFrame(frame);
    }
    window.setTimeout(hide, 15000); // fail-safe if the app never reports "done"
  }

  window.EmberBoot = {
    active: true,
    step: function (text, state) { addLine(text, state); },
    progress: function (f) { if (bar) bar.style.width = Math.round(Math.max(0, Math.min(1, f)) * 100) + "%"; },
    done: function () {
      var wait = Math.max(0, MIN_MS - (Date.now() - started));
      window.setTimeout(hide, wait);
    },
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
