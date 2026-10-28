// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// settings.js – disables the ACME fields of the Settings page's TLS & domain
// section while tls_mode off is selected: they are not saved then. Kept in a
// static file because the CSP forbids inline script; the listener is on the
// document, so it survives htmx page swaps.
document.addEventListener("change", function (e) {
  var mode = e.target;
  if (mode.name !== "tls_mode" || !mode.form) {
    return;
  }
  mode.form.querySelectorAll("[data-acme]").forEach(function (el) {
    el.disabled = mode.value === "off";
  });
});
