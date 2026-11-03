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

  document.documentElement.classList.add("js");
  // Reveal on scroll (skipped for reduced motion / no IntersectionObserver)
  var els = document.querySelectorAll(".reveal");
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduce && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    els.forEach(function (el) { el.classList.add("pre"); io.observe(el); });
  }

  // Scroll progress bar
  var bar = document.querySelector(".progress");
  if (!reduce && bar) {
    var tick = false;
    window.addEventListener("scroll", function () {
      if (tick) return; tick = true;
      requestAnimationFrame(function () {
        var max = document.documentElement.scrollHeight - window.innerHeight;
        bar.style.transform = "scaleX(" + (max > 0 ? window.scrollY / max : 0) + ")";
        tick = false;
      });
    }, { passive: true });
  }

  // "How it works": stamp the pinned record as each step scrolls into view
  var steps = document.querySelectorAll(".step"), stamps = document.querySelectorAll(".stamp");
  function setStep(n) {
    steps.forEach(function (s) { s.classList.toggle("on", +s.dataset.s === n); });
    stamps.forEach(function (s) { s.classList.toggle("on", +s.dataset.s <= n); });
  }
  if (steps.length && "IntersectionObserver" in window) {
    setStep(1);
    var so = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) setStep(+en.target.dataset.s); });
    }, { rootMargin: "-40% 0px -45% 0px" });
    steps.forEach(function (s) { so.observe(s); });
  } else {
    steps.forEach(function (s) { s.classList.add("on"); });
    stamps.forEach(function (s) { s.classList.add("on"); });
  }

  // Ask the record: sample answers (static, illustrative)
  var A = [
    { q: "Why was this refused?", r: [["Decision", "Loan limit request, applicant 4471: declined"], ["Inputs used", "Income band, repayment history, requested amount"], ["Steps", "Score 412 below threshold 500, then policy rule R-7 applied"], ["Tested on", "212 cases before release; last run passed"]] },
    { q: "What changed last week?", r: [["Change", "Prompt revision v14 to v15, support assistant"], ["Re-test", "Ran automatically; 1 of 38 checks regressed"], ["Action", "Release held; owner notified; fix reviewed and re-tested"], ["Filed", "Review and sign-off attached to the record"]] },
    { q: "Who owns this system?", r: [["System", "Credit scoring model"], ["Owner", "Risk team"], ["Data touched", "Applicant financial history"], ["Reviews", "Quarterly review on file; next review scheduled"]] }
  ];
  var ans = document.getElementById("answer"), tabs = document.querySelectorAll(".chips button");
  function show(i) {
    var d = A[i], h = "<q>“" + d.q + "”</q><dl>";
    d.r.forEach(function (x) { h += "<dt>" + x[0] + "</dt><dd>" + x[1] + "</dd>"; });
    ans.innerHTML = h + "</dl>";
    ans.classList.remove("swap"); void ans.offsetWidth; ans.classList.add("swap");
    tabs.forEach(function (t, k) { t.setAttribute("aria-selected", k === i); });
  }
  if (ans) {
    tabs.forEach(function (t, k) { t.addEventListener("click", function () { show(k); }); });
    show(0);
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
