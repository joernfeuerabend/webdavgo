// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// password.js: the button that hides or shows a suggested password (template
// "password-field" in users.html). Kept in a static file because the CSP
// forbids inline script. The listeners are on the document, so they survive
// htmx page swaps.
//
// The field is visible by default. "New suggestion" replaces the whole
// field, so the hidden state is kept on the enclosing form and applied to
// the new field when htmx loads it.
(function () {
  function apply(field, hidden) {
    var input = field.querySelector("input");
    var btn = field.querySelector("[data-password-toggle]");
    if (!input || !btn) {
      return;
    }
    input.type = hidden ? "password" : "text";
    btn.setAttribute("aria-pressed", hidden ? "false" : "true");
    btn.title = hidden ? "Show password" : "Hide password";
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-password-toggle]");
    if (!btn) {
      return;
    }
    var field = btn.closest(".password-field");
    if (!field) {
      return;
    }
    var hidden = btn.getAttribute("aria-pressed") === "true";
    var form = field.closest("form");
    if (form) {
      form.dataset.passwordHidden = hidden ? "1" : "";
    }
    apply(field, hidden);
  });

  document.addEventListener("htmx:load", function (e) {
    var elt = e.target;
    if (!elt.matches || !elt.matches(".password-field")) {
      return;
    }
    var form = elt.closest("form");
    if (form && form.dataset.passwordHidden === "1") {
      apply(elt, true);
    }
  });
})();
