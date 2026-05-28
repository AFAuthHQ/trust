// Auto-notify the agent's loopback callback after the human confirms
// a link request. Served same-origin under CSP `script-src 'self'`,
// no inline <script> needed.
//
// The trust attestor only accepts loopback (127.0.0.1 / localhost)
// callback URLs at /v1/link/start, so this script trusts the value
// it gets from data-callback — but it re-validates anyway as
// defense-in-depth before issuing the navigation.
(function () {
  var self = document.currentScript;
  if (!self) return;
  var cb = self.getAttribute('data-callback') || '';
  if (!cb) return;

  // Defensive parse: refuse anything that isn't a loopback URL on a
  // numeric port. A non-loopback target would be a server-side bug;
  // refusing to navigate is safer than redirecting the human off-site.
  var u;
  try {
    u = new URL(cb);
  } catch (_) {
    return;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') return;

  // Small delay so the human sees "Linked." before the tab navigates
  // (matches the original inline-script behaviour). The CLI's loopback
  // server returns immediately and the agent is unblocked.
  setTimeout(function () {
    window.location.href = cb;
  }, 1200);
})();
