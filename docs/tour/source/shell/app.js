(function () {
  "use strict";

  // Offline edition: everything lives in this one file. Progress is kept in
  // this browser's localStorage and can be exported/imported as JSON.
  var LS_KEY = "myotis-rust-tour:v2";
  var LS_LAST = "myotis-rust-tour:v2:last";
  var LS_SCROLL = "myotis-rust-tour:v2:scroll";
  var READING = JSON.parse(document.getElementById("reading-data").textContent);
  var CONCEPTS = READING.concepts;
  var SOURCES = READING.sources || {};

  // ---------------------------------------------------------------- helpers
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") n.className = v;
        else if (k === "text") n.textContent = v;
        else if (k === "html") n.innerHTML = v;
        else if (k.slice(0, 2) === "on") n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? "" : v);
      });
    }
    (kids || []).forEach(function (c) {
      if (c == null) return;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }
  function lsGet(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } }
  function lsSet(key, val) { try { window.localStorage.setItem(key, val); return true; } catch (e) { return false; } }
  function now() { return Date.now(); }

  // ---------------------------------------------------------------- quiz data
  var QUIZ = {};        // qid -> question (with .stop)
  var STOP_QS = {};     // stopId -> [qid]
  $all("script.quiz-data").forEach(function (s) {
    var stopId = s.getAttribute("data-stop");
    var list = JSON.parse(s.textContent);
    STOP_QS[stopId] = [];
    list.forEach(function (q) {
      q.stop = stopId;
      QUIZ[q.id] = q;
      STOP_QS[stopId].push(q.id);
    });
  });
  var TOTAL_Q = Object.keys(QUIZ).length;

  // ---------------------------------------------------------------- state
  var state = { answers: {} };
  try {
    var saved = JSON.parse(lsGet(LS_KEY) || "null");
    if (saved && saved.answers) state = saved;
  } catch (e) { /* ignore a corrupt cache */ }
  var storageOk = lsSet(LS_KEY + ":probe", "1");

  function saveLocal() { lsSet(LS_KEY, JSON.stringify(state)); }
  function record(qid, entry) {
    entry.at = now();
    state.answers[qid] = entry;
    saveLocal();
    refreshScores();
  }
  function forget(qid) {
    delete state.answers[qid];
    saveLocal();
    refreshScores();
  }

  // ---------------------------------------------------------------- scoring
  function entryScore(e) {
    if (!e) return null;
    if (e.k === "mcq") return e.ok ? 1 : 0;
    if (e.verdict === "correct") return 1;
    if (e.verdict === "partial") return 0.5;
    if (e.verdict === "incorrect") return 0;
    return null;
  }
  function conceptStats() {
    var stats = {};
    Object.keys(CONCEPTS).forEach(function (c) { stats[c] = { n: 0, sum: 0, total: 0 }; });
    Object.keys(QUIZ).forEach(function (qid) {
      var q = QUIZ[qid];
      var s = entryScore(state.answers[qid]);
      (q.tags || []).forEach(function (t) {
        if (!stats[t]) return;
        stats[t].total += 1;
        if (s != null) { stats[t].n += 1; stats[t].sum += s; }
      });
    });
    Object.keys(stats).forEach(function (c) {
      var st = stats[c];
      st.score = st.n ? st.sum / st.n : null;
      if (!st.n) st.level = "none";
      else if (st.score >= 0.8) st.level = "good";
      else if (st.score >= 0.55 || st.n < 2) st.level = "shaky";
      else st.level = "struggling";
    });
    return stats;
  }

  function refreshScores() {
    var answered = 0;
    Object.keys(STOP_QS).forEach(function (stopId) {
      var qs = STOP_QS[stopId];
      var done = qs.filter(function (qid) { return entryScore(state.answers[qid]) != null; }).length;
      answered += done;
      var link = $('.route a[data-stop="' + stopId + '"]');
      if (!link) return;
      var sc = $(".score", link);
      if (sc) sc.textContent = qs.length ? done + "/" + qs.length : "";
      link.classList.toggle("done", qs.length > 0 && done === qs.length);
      var tally = $('.checkpoint[data-stop="' + stopId + '"] .tally');
      if (tally) {
        var right = qs.reduce(function (acc, qid) { var s = entryScore(state.answers[qid]); return acc + (s || 0); }, 0);
        tally.textContent = done + " of " + qs.length + " answered · " + formatScore(right) + " points";
      }
    });
    var m = $("#progress-meter");
    if (m) m.textContent = answered + " / " + TOTAL_Q;
    if (currentStop === "progress") renderProgress();
  }
  function formatScore(x) { return (Math.round(x * 10) / 10).toString(); }

  // ---------------------------------------------------------------- reading suggestions
  function readNextBox(q) {
    var tag = (q.tags || [])[0];
    var c = tag && CONCEPTS[tag];
    if (!c) return null;
    var box = el("div", { class: "readnext" }, [el("b", { text: "If this felt shaky, read" })]);
    c.items.slice(0, 2).forEach(function (it) { box.appendChild(readingLine(it)); });
    box.appendChild(el("a", { href: "#progress", text: "All suggestions for “" + c.label + "” →" }));
    return box;
  }
  function readingLine(it) {
    var line = el("div", { class: "rl" });
    line.appendChild(el("span", { class: "src", text: it.src }));
    if (it.href) line.appendChild(el("a", { href: it.href, target: "_blank", rel: "noopener", text: it.title }));
    else line.appendChild(el("span", { text: it.title }));
    if (it.offline) line.appendChild(el("span", { class: "offline-ok", text: "offline" }));
    if (it.note) line.appendChild(el("span", { class: "rl-note", text: " " + it.note }));
    return line;
  }

  // ---------------------------------------------------------------- quiz rendering
  function htmlToText(html) {
    var d = document.createElement("div");
    d.innerHTML = html;
    return (d.textContent || "").replace(/\s+/g, " ").trim();
  }

  function renderQuestion(q, index) {
    q.qText = htmlToText(q.q);
    var card = el("div", { class: "q", id: "q-" + q.id, "data-qid": q.id });
    card.appendChild(el("div", { class: "q-top" }, [
      el("span", { class: "q-num", text: "Question " + (index + 1) }),
      el("span", { class: "q-kind", text: q.type === "mcq" ? "Pick one" : "Explain in your own words" })
    ]));
    card.appendChild(el("div", { class: "q-text", html: q.q }));
    var verdict = el("div", { class: "verdict", hidden: true, "aria-live": "polite" });
    if (q.type === "mcq") renderMcq(q, card, verdict);
    else renderOpen(q, card, verdict);
    card.appendChild(verdict);
    return card;
  }

  function renderMcq(q, card, verdict) {
    var name = "opt-" + q.id;
    var opts = el("div", { class: "opts", role: "radiogroup", "aria-label": "Answer options" });
    q.options.forEach(function (o, i) {
      var input = el("input", { type: "radio", name: name, value: String(i) });
      opts.appendChild(el("label", { class: "opt" }, [input, el("span", { html: o })]));
    });
    card.appendChild(opts);
    var check = el("button", { class: "btn primary", type: "button", text: "Check answer", disabled: true });
    var retry = el("button", { class: "btn ghost", type: "button", text: "Reset this question", hidden: true });
    card.appendChild(el("div", { class: "q-actions" }, [check, retry]));
    opts.addEventListener("change", function () { if (!card.classList.contains("locked")) check.disabled = false; });

    function show(entry) {
      card.classList.add("locked");
      check.disabled = true;
      check.hidden = true;
      retry.hidden = false;
      $all("input", opts).forEach(function (inp, i) {
        inp.disabled = true;
        inp.checked = i === entry.first;
        var lab = inp.closest(".opt");
        lab.classList.toggle("is-right", i === q.answer);
        lab.classList.toggle("is-wrong", i === entry.first && i !== q.answer);
      });
      verdict.innerHTML = "";
      verdict.appendChild(el("span", { class: "pill " + (entry.ok ? "ok" : "bad"), text: entry.ok ? "Correct" : "Not quite" }));
      verdict.appendChild(el("div", { html: q.explain }));
      if (!entry.ok) { var rn = readNextBox(q); if (rn) verdict.appendChild(rn); }
      verdict.hidden = false;
    }
    function reset() {
      card.classList.remove("locked");
      check.hidden = false;
      retry.hidden = true;
      verdict.hidden = true;
      $all("input", opts).forEach(function (inp) {
        inp.disabled = false; inp.checked = false;
        inp.closest(".opt").classList.remove("is-right", "is-wrong");
      });
      check.disabled = true;
    }
    check.addEventListener("click", function () {
      var picked = $("input:checked", opts);
      if (!picked) return;
      var i = Number(picked.value);
      var entry = { k: "mcq", first: i, ok: i === q.answer };
      record(q.id, entry);
      show(entry);
    });
    retry.addEventListener("click", function () { forget(q.id); reset(); });
    card._restore = function () {
      var e = state.answers[q.id];
      if (e && e.k === "mcq") show(e); else reset();
    };
  }

  // Open questions are self-graded offline: write your answer, then compare
  // it with the model answer and tick the key points your answer covered.
  function verdictFor(ticked, total) {
    if (!total) return "partial";
    var r = ticked / total;
    return r >= 0.8 ? "correct" : r >= 0.4 ? "partial" : "incorrect";
  }
  function verdictLabel(v) {
    return v === "correct" ? "Got it" : v === "partial" ? "Partly" : "Missed it";
  }
  function renderOpen(q, card, verdict) {
    var ta = el("textarea", { class: "answer", placeholder: "Write your explanation first. Two to five sentences is plenty.", "aria-label": "Your answer", maxlength: "3000" });
    card.appendChild(ta);
    var compare = el("button", { class: "btn primary", type: "button", text: "Compare with the model answer" });
    var retry = el("button", { class: "btn ghost", type: "button", text: "Answer again", hidden: true });
    var status = el("span", { class: "hint" });
    card.appendChild(el("div", { class: "q-actions" }, [compare, retry, status]));

    ta.addEventListener("input", function () {
      var d = lsGet(LS_KEY + ":draft:" + q.id);
      if (ta.value !== d) lsSet(LS_KEY + ":draft:" + q.id, ta.value);
    });

    function modelBlock() {
      return el("div", { class: "model" }, [el("b", { text: "Model answer" }), el("div", { html: q.model })]);
    }
    function checklist(ticks, locked) {
      var box = el("fieldset", { class: "points" }, [el("legend", { text: "Tick each key point your answer covered" })]);
      (q.points || []).forEach(function (p, i) {
        var cb = el("input", { type: "checkbox", value: String(i) });
        if (ticks && ticks.indexOf(i) >= 0) cb.checked = true;
        if (locked) cb.disabled = true;
        box.appendChild(el("label", { class: "point" }, [cb, el("span", { html: p })]));
      });
      return box;
    }
    function showGrading() {
      verdict.innerHTML = "";
      verdict.appendChild(el("span", { class: "pill info", text: "Grade yourself" }));
      verdict.appendChild(modelBlock());
      var cl = checklist([], false);
      verdict.appendChild(cl);
      var save = el("button", { class: "btn primary", type: "button", text: "Save my grade" });
      var hint = el("span", { class: "hint", text: "80% of the points or more counts as correct, 40% or more as partly." });
      verdict.appendChild(el("div", { class: "q-actions" }, [save, hint]));
      save.addEventListener("click", function () {
        var ticks = $all("input:checked", cl).map(function (i) { return Number(i.value); });
        var v = verdictFor(ticks.length, (q.points || []).length);
        var entry = { k: "open", by: "self", verdict: v, ticks: ticks, text: ta.value.slice(0, 3000) };
        record(q.id, entry);
        showEntry(entry);
      });
      verdict.hidden = false;
      compare.hidden = true;
    }
    function showEntry(e) {
      verdict.innerHTML = "";
      var cls = e.verdict === "correct" ? "ok" : e.verdict === "partial" ? "part" : "bad";
      verdict.appendChild(el("span", { class: "pill " + cls, text: verdictLabel(e.verdict) + (e.ticks ? " · " + e.ticks.length + " of " + (q.points || []).length + " points" : "") }));
      verdict.appendChild(modelBlock());
      if (e.ticks) verdict.appendChild(checklist(e.ticks, true));
      if (e.verdict !== "correct") { var rn = readNextBox(q); if (rn) verdict.appendChild(rn); }
      verdict.hidden = false;
      if (e.text != null) ta.value = e.text;
      ta.readOnly = true;
      compare.hidden = true;
      retry.hidden = false;
    }
    compare.addEventListener("click", function () {
      if (!ta.value.trim()) {
        status.textContent = "Write your answer first; comparing is the point.";
        return;
      }
      status.textContent = "";
      showGrading();
    });
    retry.addEventListener("click", function () {
      forget(q.id);
      ta.readOnly = false;
      verdict.hidden = true;
      compare.hidden = false;
      retry.hidden = true;
      ta.focus();
    });
    card._restore = function () {
      var e = state.answers[q.id];
      if (e && e.k === "open") showEntry(e);
      else {
        ta.readOnly = false;
        ta.value = lsGet(LS_KEY + ":draft:" + q.id) || "";
        verdict.hidden = true;
        compare.hidden = false;
        retry.hidden = true;
      }
    };
  }

  $all(".checkpoint").forEach(function (cp) {
    var stopId = cp.getAttribute("data-stop");
    var host = $(".q-list", cp);
    (STOP_QS[stopId] || []).forEach(function (qid, i) {
      var card = renderQuestion(QUIZ[qid], i);
      host.appendChild(card);
      card._restore();
    });
  });

  function restoreAll() {
    $all(".q").forEach(function (c) { if (c._restore) c._restore(); });
    refreshScores();
  }

  // ---------------------------------------------------------------- export / import
  function exportJson() {
    return JSON.stringify({ format: "myotis-rust-tour-progress", version: 2, exported: new Date().toISOString(), answers: state.answers });
  }
  function importJson(text) {
    var data = JSON.parse(text);
    var incoming = data && data.answers;
    if (!incoming || typeof incoming !== "object") throw new Error("This doesn't look like an exported progress file.");
    var added = 0, kept = 0;
    Object.keys(incoming).forEach(function (qid) {
      if (!QUIZ[qid]) return;
      var mine = state.answers[qid];
      var theirs = incoming[qid];
      if (!mine || (theirs.at || 0) > (mine.at || 0)) { state.answers[qid] = theirs; added += 1; }
      else kept += 1;
    });
    saveLocal();
    restoreAll();
    return { added: added, kept: kept };
  }
  function summaryText(stats, answered, pct) {
    var lines = ["Myotis Rust Tour — my results (" + answered + "/" + TOTAL_Q + " answered, " + pct + "%)."];
    Object.keys(CONCEPTS).forEach(function (c) {
      var st = stats[c];
      if (st.n) lines.push("- " + CONCEPTS[c].label + ": " + Math.round(st.score * 100) + "% over " + st.n + " (" + levelText(st.level) + ")");
    });
    var missed = Object.keys(QUIZ).filter(function (qid) { var s = entryScore(state.answers[qid]); return s != null && s < 1; });
    if (missed.length) {
      lines.push("Questions I missed or only partly answered:");
      missed.forEach(function (qid) {
        var e = state.answers[qid];
        lines.push("- [" + QUIZ[qid].stop + " " + qid + "] " + QUIZ[qid].qText);
        if (e.k === "open" && e.text) lines.push("  My answer: " + e.text.replace(/\s+/g, " ").slice(0, 600));
      });
    }
    return lines.join("\n");
  }
  function copyOrShow(text, out, note, okMsg) {
    out.value = text;
    var fallback = function () { out.hidden = false; out.focus(); out.select(); note.textContent = "Select the text below and copy it."; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { note.textContent = okMsg; }, fallback);
    } else fallback();
  }

  // ---------------------------------------------------------------- progress view
  function renderProgress() {
    var host = $("#progress-body");
    if (!host) return;
    var stats = conceptStats();
    host.innerHTML = "";

    var answered = 0, points = 0;
    Object.keys(QUIZ).forEach(function (qid) {
      var s = entryScore(state.answers[qid]);
      if (s != null) { answered += 1; points += s; }
    });
    var pct = answered ? Math.round((points / answered) * 100) : 0;
    host.appendChild(el("div", { class: "summary-row" }, [
      el("div", { class: "fig" }, [el("b", { text: answered + " / " + TOTAL_Q }), el("span", { text: "questions answered" })]),
      el("div", { class: "fig" }, [el("b", { text: answered ? pct + "%" : "—" }), el("span", { text: "score on answered questions" })]),
      el("div", { class: "fig" }, [el("b", { text: String(Object.keys(stats).filter(function (c) { return stats[c].level === "struggling"; }).length) }), el("span", { text: "concepts to revisit" })])
    ]));
    if (!storageOk) {
      host.appendChild(el("div", { class: "callout watch" }, [el("span", { class: "k", text: "Progress is not being saved" }),
        el("p", { text: "This browser blocks local storage for this page, so answers vanish when you close it. Open the file in Safari, Chrome or Firefox directly from Finder, and export your progress before closing." })]));
    }

    var ranked = Object.keys(stats)
      .filter(function (c) { return stats[c].level === "struggling" || stats[c].level === "shaky"; })
      .sort(function (a, b) { return stats[a].score - stats[b].score || stats[b].n - stats[a].n; });

    host.appendChild(el("h2", { class: "section-title", text: ranked.length ? "Your reading list" : "Suggested reading" }));
    host.appendChild(el("p", { class: "code-note", text: ranked.length
      ? "Built from your answers: the weakest concepts come first. Items marked “offline” open without a network: your EPUBs in Apple Books, and the Rust docs installed with rustup."
      : (answered ? "Nothing looks shaky so far. If you want to go deeper anyway, these are the best chapters for the memory model."
                  : "Once you answer checkpoint questions, this list reorders itself around your weak spots. Until then, here is where to read up on the memory model.") }));

    var list = ranked.length ? ranked : ["ownership", "borrowing", "lifetimes", "smart-pointers", "interior-mutability", "async"];
    var grid = el("div", { class: "reading" });
    list.forEach(function (c) {
      var info = CONCEPTS[c];
      if (!info) return;
      var st = stats[c];
      var head = el("div", { class: "q-top" }, [
        el("h3", { text: info.label }),
        el("span", { class: "state " + st.level, text: levelText(st.level) })
      ]);
      var ol = el("ol");
      info.items.forEach(function (it) { ol.appendChild(el("li", {}, [readingLine(it)])); });
      var card = el("div", { class: "reading-card" }, [head, el("p", { class: "hint", text: info.blurb }), ol]);
      if (info.stop) card.appendChild(el("a", { href: "#" + info.stop, text: "Revisit in the tour: " + info.stopLabel }));
      grid.appendChild(card);
    });
    host.appendChild(grid);

    host.appendChild(el("h2", { class: "section-title", text: "By concept" }));
    var tbl = el("table", { class: "concept-table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: "Concept" }), el("th", { text: "Answered" }), el("th", { text: "Score" }), el("th", { text: "" }), el("th", { text: "State" })
    ])]));
    var tb = el("tbody");
    Object.keys(CONCEPTS).forEach(function (c) {
      var st = stats[c];
      if (!st.total) return;
      var w = st.score == null ? 0 : Math.round(st.score * 100);
      var bar = el("div", { class: "bar" }, [el("i", { class: st.score == null ? "" : st.score >= 0.8 ? "" : st.score >= 0.55 ? "mid" : "low", style: "width:" + w + "%" })]);
      tb.appendChild(el("tr", {}, [
        el("td", {}, [el("a", { class: "tag", href: "#primer-" + c, text: CONCEPTS[c].label })]),
        el("td", { class: "num", text: st.n + " of " + st.total }),
        el("td", { class: "num", text: st.score == null ? "—" : w + "%" }),
        el("td", {}, [bar]),
        el("td", {}, [el("span", { class: "state " + st.level, text: levelText(st.level) })])
      ]));
    });
    tbl.appendChild(tb);
    host.appendChild(el("div", { class: "table-wrap" }, [tbl]));

    // Take results back to Claude, or move them between browsers.
    host.appendChild(el("h2", { class: "section-title", text: "Keep or share your results" }));
    host.appendChild(el("p", { class: "code-note", text: "Your answers live only in this browser. Export them to keep a copy or to move them to another browser. After the flight, copy the summary into a Claude session so your weak spots can be gone through together." }));
    var out = el("textarea", { class: "answer", readonly: true, hidden: true, "aria-label": "Exported text" });
    var note = el("span", { class: "hint" });
    var copyBtn = el("button", { class: "btn primary", type: "button", text: "Copy a summary for Claude" });
    copyBtn.addEventListener("click", function () { copyOrShow(summaryText(stats, answered, pct), out, note, "Copied. Paste it into a Claude session."); });
    var dlBtn = el("button", { class: "btn", type: "button", text: "Download progress file" });
    dlBtn.addEventListener("click", function () {
      try {
        var blob = new Blob([exportJson()], { type: "application/json" });
        var a = el("a", { href: URL.createObjectURL(blob), download: "myotis-rust-tour-progress.json" });
        document.body.appendChild(a); a.click(); a.remove();
        note.textContent = "Saved as myotis-rust-tour-progress.json.";
      } catch (e) { copyOrShow(exportJson(), out, note, "Copied the progress JSON."); }
    });
    var cpJson = el("button", { class: "btn", type: "button", text: "Copy progress JSON" });
    cpJson.addEventListener("click", function () { copyOrShow(exportJson(), out, note, "Copied the progress JSON."); });
    host.appendChild(el("div", { class: "q-actions" }, [copyBtn, dlBtn, cpJson, note]));
    host.appendChild(out);

    var inTa = el("textarea", { class: "answer", placeholder: "Paste exported progress JSON here", "aria-label": "Progress to import" });
    var inBtn = el("button", { class: "btn", type: "button", text: "Import progress" });
    var inNote = el("span", { class: "hint" });
    var file = el("input", { type: "file", accept: "application/json,.json", "aria-label": "Progress file" });
    file.addEventListener("change", function () {
      var f = file.files && file.files[0];
      if (!f) return;
      var r = new FileReader();
      r.onload = function () { inTa.value = String(r.result || ""); };
      r.readAsText(f);
    });
    inBtn.addEventListener("click", function () {
      try {
        var res = importJson(inTa.value);
        inNote.textContent = "Imported " + res.added + " answers (" + res.kept + " newer ones here were kept).";
        renderProgress();
      } catch (e) { inNote.textContent = e.message || "Could not read that JSON."; }
    });
    host.appendChild(el("details", { class: "deep" }, [el("summary", { text: "Import progress from another browser" }), inTa, el("div", { class: "q-actions" }, [file, inBtn, inNote])]));
  }
  function levelText(l) {
    return l === "good" ? "solid" : l === "shaky" ? "shaky" : l === "struggling" ? "struggling" : "not tested yet";
  }

  // ---------------------------------------------------------------- routing
  var currentStop = null;
  function saveScroll() {
    if (!currentStop || currentStop === "progress") return;
    var pos = {};
    try { pos = JSON.parse(lsGet(LS_SCROLL) || "{}") || {}; } catch (e) { pos = {}; }
    pos[currentStop] = window.scrollY;
    lsSet(LS_SCROLL, JSON.stringify(pos));
  }
  function savedScroll(id) {
    try { return (JSON.parse(lsGet(LS_SCROLL) || "{}") || {})[id] || 0; } catch (e) { return 0; }
  }
  var scrollTimer = null;
  window.addEventListener("scroll", function () {
    if (scrollTimer) clearTimeout(scrollTimer);
    scrollTimer = setTimeout(saveScroll, 400);
  }, { passive: true });

  function showStop(id) {
    saveScroll();
    $all(".stop").forEach(function (s) { s.hidden = s.id !== id; });
    $all(".route a").forEach(function (a) {
      if (a.getAttribute("data-stop") === id) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    var progressLink = $("#progress-link");
    if (progressLink) {
      if (id === "progress") progressLink.setAttribute("aria-current", "page");
      else progressLink.removeAttribute("aria-current");
    }
    currentStop = id;
    if (id === "progress") renderProgress();
    else lsSet(LS_LAST, id);
    closeRail();
  }
  function route(initial) {
    var h = decodeURIComponent(location.hash.replace(/^#/, ""));
    var target = h ? document.getElementById(h) : null;
    if (!target) target = document.getElementById(lsGet(LS_LAST) || "") || document.getElementById("stop-00");
    var stop = target.classList.contains("stop") ? target : target.closest(".stop");
    if (!stop) { stop = document.getElementById("stop-00"); target = stop; }
    showStop(stop.id);
    if (target !== stop) {
      requestAnimationFrame(function () { target.scrollIntoView({ block: "start" }); });
    } else if (initial === true && !h) {
      var y = savedScroll(stop.id);
      requestAnimationFrame(function () { window.scrollTo(0, y); });
    } else {
      window.scrollTo(0, 0);
    }
  }
  window.addEventListener("hashchange", function () { route(false); });

  // mobile rail
  var rail = $(".rail");
  var scrim = $(".scrim");
  function closeRail() { if (rail) rail.classList.remove("open"); if (scrim) scrim.hidden = true; }
  var menuBtn = $("#menu-btn");
  if (menuBtn) menuBtn.addEventListener("click", function () { rail.classList.add("open"); scrim.hidden = false; });
  if (scrim) scrim.addEventListener("click", closeRail);

  // copy buttons on workbook code blocks
  $all("pre[data-copy]").forEach(function (pre) {
    var b = el("button", { class: "btn ghost copy-btn", type: "button", text: "Copy" });
    b.addEventListener("click", function () {
      var t = pre.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(t).then(function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1500); });
      }
    });
    pre.parentNode.insertBefore(b, pre);
  });

  document.documentElement.classList.add("js");
  route(true);
  refreshScores();
  var sync = $("#sync-note");
  if (sync) sync.textContent = storageOk
    ? "Progress is saved in this browser. Export it from the progress page to keep a copy."
    : "This browser blocks local storage here: answers are lost on close. Export them before you quit.";
})();
