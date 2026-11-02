// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// update.js – the "Install update" flow of the Update page. Kept in a static
// file because the CSP forbids inline script; the listeners are on the
// document, so they survive htmx page swaps.
//
// The install form is not boosted, so hx-confirm would not apply to it.
// Its submit is held back until the admin confirms in #update-confirm.
//
// While a request waits for the update helper, the page polls
// /admin/update. If the helper reports a failure, the old process is still
// running and a reload shows the error. Once /admin/update stops responding
// or sends the login page, the service is restarting: from then on only
// /admin/login is checked, and the browser goes there when it responds.
(function () {
  var interval = 2000;
  var pendingLimit = 5 * 60 * 1000;
  var restartHint = 3 * 60 * 1000;
  var requestTimeout = 10000;

  // get fetches url without following redirects. A request that hangs
  // counts as no response.
  function get(url) {
    var ctl = new AbortController();
    var t = setTimeout(function () { ctl.abort(); }, requestTimeout);
    return fetch(url, { cache: "no-store", credentials: "same-origin", redirect: "manual", signal: ctl.signal })
      .finally(function () { clearTimeout(t); });
  }

  // ---- confirmation ----

  document.addEventListener("submit", function (e) {
    var form = e.target;
    var id = form.getAttribute && form.getAttribute("data-update-confirm");
    if (!id) {
      return;
    }
    if (form.dataset.updateConfirmed === "1") {
      var btn = form.querySelector("button[type=submit]");
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Downloading update…";
      }
      return;
    }
    var dialog = document.getElementById(id);
    if (!dialog || typeof dialog.showModal !== "function") {
      return;
    }
    e.preventDefault();
    dialog.showModal();
  });

  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!t.closest) {
      return;
    }
    var dialog = t.closest("dialog");
    if (!dialog) {
      return;
    }
    if (t.closest("[data-update-cancel]")) {
      dialog.close();
    } else if (t.closest("[data-update-confirmed]")) {
      var form = document.querySelector('form[data-update-confirm="' + dialog.id + '"]');
      dialog.close();
      if (form) {
        form.dataset.updateConfirmed = "1";
        form.requestSubmit();
      }
    }
  });

  // ---- progress ----

  function show(el, text) {
    el.textContent = text;
  }

  function waitForLogin(el) {
    show(el, "The update is being installed and the service is restarting. Connections are interrupted briefly and you are logged out. The login page opens as soon as the service responds again.");
    var started = Date.now();
    var hinted = false;
    function check() {
      get("/admin/login")
        .then(function (res) {
          if (res.ok) {
            window.location.replace("/admin/login");
            return;
          }
          next();
        }, next);
    }
    function next() {
      if (!hinted && Date.now() - started > restartHint) {
        hinted = true;
        show(el, "The service has not responded for a while. This page keeps checking and opens the login page as soon as the service responds again. On the server, journalctl -u webdavgo and journalctl -u webdavgo-update show what happened.");
      }
      setTimeout(check, interval);
    }
    setTimeout(check, interval);
  }

  function watchPending(el) {
    show(el, "The update has been handed to the update helper and is being installed. This page checks the progress every few seconds.");
    var started = Date.now();
    function check() {
      if (!el.isConnected) {
        return;
      }
      get("/admin/update")
        .then(function (res) {
          if (!el.isConnected) {
            return;
          }
          // The only redirect /admin/update sends is to the login page:
          // the restarted service no longer knows this session.
          if (res.type === "opaqueredirect") {
            waitForLogin(el);
            return;
          }
          if (!res.ok) {
            next();
            return;
          }
          return res.text().then(function (html) {
            var doc = new DOMParser().parseFromString(html, "text/html");
            if (doc.querySelector('form[action="/admin/login"]')) {
              waitForLogin(el);
            } else if (doc.querySelector("[data-update-pending]")) {
              next();
            } else {
              // The helper is done and this process still runs: the
              // reloaded page shows its report.
              window.location.replace("/admin/update");
            }
          });
        })
        .catch(function () {
          if (el.isConnected) {
            waitForLogin(el);
          }
        });
    }
    function next() {
      if (Date.now() - started > pendingLimit) {
        show(el, "The update helper has not reported back yet. Reload this page to check again.");
        return;
      }
      setTimeout(check, interval);
    }
    setTimeout(check, interval);
  }

  function start() {
    var el = document.getElementById("update-progress");
    if (!el || !el.hasAttribute("data-update-pending") || el.dataset.watching === "1") {
      return;
    }
    el.dataset.watching = "1";
    watchPending(el);
  }

  document.addEventListener("DOMContentLoaded", start);
  document.addEventListener("htmx:afterSettle", start);
})();
