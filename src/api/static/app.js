/* app.js — the dashboard's only script. First-party, self-hosted, ~60 lines.
 *
 * PROGRESSIVE ENHANCEMENT, STRICTLY
 * Every page works with this file blocked or disabled: the filters are a real
 * <form> with a real submit button, the triage controls are real POSTs, and
 * pagination is real links. Nothing here fetches, and nothing here is required.
 * That is deliberate — a security tool whose evidence page depends on
 * JavaScript executing correctly is one bug away from showing an analyst the
 * wrong thing.
 *
 * It makes no network requests of any kind. See docs/ethics-and-containment.md.
 */
(function () {
  "use strict";

  /* Submit the alert filters when a dropdown changes, so filtering is one
     click instead of two. The submit button stays, for keyboard users and for
     anyone who has scripting off. */
  function autoSubmitFilters() {
    document.querySelectorAll("form[data-autosubmit]").forEach(function (form) {
      form.querySelectorAll("select").forEach(function (select) {
        select.addEventListener("change", function () {
          form.submit();
        });
      });
    });
  }

  /* A status change writes history and an audit row that cannot be removed, so
     a misclick is permanent in the record even when it is corrected. One
     confirmation for the two terminal-ish moves is worth the friction. */
  var CONFIRM_FOR = ["Closed", "Benign", "Confirmed suspicious"];

  function confirmTerminalTransitions() {
    document.querySelectorAll('form[action$="/status"]').forEach(function (form) {
      form.addEventListener("submit", function (event) {
        var select = form.querySelector('select[name="status"]');
        if (!select) { return; }
        var target = select.value;
        if (CONFIRM_FOR.indexOf(target) === -1) { return; }
        var ok = window.confirm(
          'Move this alert to "' + target + '"? The transition is recorded in ' +
          "the audit trail and cannot be deleted.");
        if (!ok) { event.preventDefault(); }
      });
    });
  }

  /* Clear the one-shot ?updated=1 / ?error= markers from the address bar so a
     refresh does not re-show a stale banner. Pure cosmetics; the page has
     already rendered correctly without it. */
  function tidyUrl() {
    if (!window.history || !window.history.replaceState) { return; }
    var url = new URL(window.location.href);
    if (!url.searchParams.has("updated") && !url.searchParams.has("error")) {
      return;
    }
    url.searchParams.delete("updated");
    url.searchParams.delete("error");
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
  }

  document.addEventListener("DOMContentLoaded", function () {
    autoSubmitFilters();
    confirmTerminalTransitions();
    tidyUrl();
  });
})();
