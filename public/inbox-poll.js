// Polls GET /auth/session every 3s once the "Check your inbox" page
// renders. Self-redirects to the `next` URL (taken from this script
// element's data-next attribute) the moment the magic-link click in
// another tab creates a session — so the orphan tab self-heals
// without the user having to think about it.
//
// Loaded same-origin under CSP `script-src 'self'`. No third-party
// requests. No PII in the polled endpoint by design.
(function () {
  var self = document.currentScript;
  var target = (self && self.getAttribute('data-next')) || '/account';
  // Defensive: refuse anything that isn't a same-origin path.
  if (target.indexOf('/') !== 0 || target.indexOf('//') === 0) {
    target = '/account';
  }
  var iv = setInterval(async function () {
    try {
      var r = await fetch('/auth/session', { credentials: 'same-origin' });
      if (!r.ok) return;
      var j = await r.json();
      if (j && j.authenticated === true) {
        clearInterval(iv);
        window.location.replace(target);
      }
    } catch (_) { /* network blip — try again next tick */ }
  }, 3000);
  // Cap total polling to ~30 min so an abandoned tab doesn't spin
  // forever. Matches the link-request TTL ceiling.
  setTimeout(function () { clearInterval(iv); }, 30 * 60 * 1000);
})();
