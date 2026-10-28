// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// errors.js – shows failed htmx requests on the page. htmx swaps nothing for
// 4xx/5xx responses or network errors, so without this a rejected request
// (e.g. a 403 for a stale CSRF token) would look like a dead button. Kept in
// a static file because the CSP forbids inline script.
(function () {
  function show(msg) {
    var el = document.getElementById("htmx-error");
    if (!el) {
      el = document.createElement("p");
      el.id = "htmx-error";
      el.className = "error htmx-error";
      el.setAttribute("role", "alert");
      document.body.prepend(el);
    }
    el.textContent = msg;
  }
  document.addEventListener("htmx:responseError", function (e) {
    show("Request rejected (" + e.detail.xhr.status + "). Reload the page and try again.");
  });
  document.addEventListener("htmx:sendError", function () {
    show("Request failed: server not reachable. Check the connection and try again.");
  });
})();
