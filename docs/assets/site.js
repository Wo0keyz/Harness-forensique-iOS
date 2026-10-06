// Navigation de la documentation : sommaire actif, bouton « Copier » sur les blocs de code, thème.
(function () {
  "use strict";

  // Thème : suit le système, sauf choix explicite mémorisé (préférence locale, facultative).
  var root = document.documentElement;
  var stored = null;
  try { stored = localStorage.getItem("doc-theme"); } catch (e) { /* stockage indisponible */ }
  if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);

  function currentTheme() {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.querySelector(".theme-toggle");
    if (btn) {
      var label = function () { btn.textContent = currentTheme() === "dark" ? "Thème clair" : "Thème sombre"; };
      label();
      btn.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("doc-theme", next); } catch (e) { /* sans effet */ }
        label();
      });
    }

    // Bouton « Copier » sur chaque bloc de code.
    document.querySelectorAll("pre").forEach(function (pre) {
      if (pre.classList.contains("no-copy")) return;
      var b = document.createElement("button");
      b.type = "button";
      b.className = "copy-btn";
      b.textContent = "Copier";
      b.addEventListener("click", function () {
        var code = pre.querySelector("code") || pre;
        var text = code.innerText;
        var done = function () { b.textContent = "Copié"; setTimeout(function () { b.textContent = "Copier"; }, 1400); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {});
        }
      });
      pre.appendChild(b);
    });

    // Sommaire : met en évidence la section visible.
    var links = Array.prototype.slice.call(document.querySelectorAll(".toc a[href^='#']"));
    if (!links.length || !("IntersectionObserver" in window)) return;
    var byId = {};
    links.forEach(function (a) { byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a; });
    var targets = Object.keys(byId).map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var visible = {};
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
      var first = targets.find(function (t) { return visible[t.id]; });
      if (!first) return;
      links.forEach(function (a) { a.classList.remove("active"); });
      byId[first.id].classList.add("active");
    }, { rootMargin: "-64px 0px -65% 0px" });
    targets.forEach(function (t) { obs.observe(t); });
  });
})();
