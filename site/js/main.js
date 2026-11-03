(function () {
  // Mobile nav
  var btn = document.querySelector(".nav-toggle"), nav = document.getElementById("nav");
  btn.addEventListener("click", function () {
    var open = nav.classList.toggle("open");
    btn.setAttribute("aria-expanded", open);
  });
  nav.addEventListener("click", function (e) {
    if (e.target.tagName === "A") { nav.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); }
  });

  // Reveal on scroll (skipped for reduced motion / no IntersectionObserver)
  var els = document.querySelectorAll(".reveal");
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduce && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    els.forEach(function (el) { el.classList.add("pre"); io.observe(el); });
  }

  // Scroll progress bar + gentle hero parallax (skipped for reduced motion)
  var bar = document.querySelector(".progress"), art = document.querySelector(".orbit-svg");
  if (!reduce && bar) {
    var tick = false;
    window.addEventListener("scroll", function () {
      if (tick) return; tick = true;
      requestAnimationFrame(function () {
        var max = document.documentElement.scrollHeight - window.innerHeight;
        bar.style.transform = "scaleX(" + (max > 0 ? window.scrollY / max : 0) + ")";
        if (art) art.style.setProperty("--py", Math.min(window.scrollY * 0.12, 80) + "px");
        tick = false;
      });
    }, { passive: true });
  }

  // Loop diagram: highlight each module in turn
  var nodes = document.querySelectorAll(".loop-node");
  if (nodes.length && !reduce) {
    var i = 0;
    setInterval(function () {
      nodes.forEach(function (n) { n.classList.remove("on"); });
      nodes[i++ % nodes.length].classList.add("on");
    }, 1800);
  }

  // Early-access form: nothing is sent to any server.
  var form = document.getElementById("ea-form"), status = document.getElementById("ea-status");
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var to = (window.VESK_CONFIG || {}).CONTACT_EMAIL;
    if (!to) {
      status.textContent = "Early-access requests are not open yet. This form is not connected to anything, and nothing you typed was sent.";
      return;
    }
    var f = new FormData(form);
    var body = "Name: " + f.get("name") + "\nCompany: " + f.get("company") + "\nEmail: " + f.get("email") +
      "\n\nAI systems:\n" + (f.get("systems") || "");
    window.location.href = "mailto:" + to + "?subject=" + encodeURIComponent("Vesk early access") +
      "&body=" + encodeURIComponent(body);
    status.textContent = "Your email app should open with the request ready to send.";
  });
})();

// Image placeholders: if img/<file> is missing, show a labelled placeholder.
// Drop the real file in site/img/ with the same name and it is used automatically.
(function () {
  document.querySelectorAll("img[data-ph]").forEach(function (img) {
    var optional = img.hasAttribute("data-optional");
    if (optional) {
      // Optional slot: stays hidden until the real file exists; no placeholder box.
      img.onerror = function () { img.onerror = null; };
      img.onload = function () { img.classList.add("loaded"); };
      if (img.complete && img.naturalWidth > 0) img.classList.add("loaded");
      return;
    }
    function ph() {
      var w = +img.getAttribute("width"), h = +img.getAttribute("height");
      var name = img.getAttribute("src").split("/").pop();
      var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
        '<rect width="100%" height="100%" fill="#1a2347"/><rect x="2" y="2" width="' + (w - 4) + '" height="' + (h - 4) + '" fill="none" stroke="#3a4678" stroke-width="3" stroke-dasharray="14 10"/>' +
        '<text x="50%" y="48%" fill="#e8ecf8" font-family="sans-serif" font-size="' + Math.round(w / 30) + '" text-anchor="middle">Image placeholder</text>' +
        '<text x="50%" y="58%" fill="#aab3d0" font-family="monospace" font-size="' + Math.round(w / 38) + '" text-anchor="middle">img/' + name + ' · ' + w + '×' + h + '</text></svg>';
      img.onerror = null;
      img.src = "data:image/svg+xml," + encodeURIComponent(svg);
    }
    img.onerror = ph;
    if (img.complete && img.naturalWidth === 0) ph();
  });
})();
