// Confirmation modal for the permanent "Revoke agent" action on
// /account. Revoking flips a binding's revoked_at and never clears it
// (the store only matches revoked_at IS NULL), so a single misclick
// permanently kills that binding. This intercepts the revoke <form>
// submit and gates it behind an explicit confirm that spells out the
// implications, showing which agent is about to be cut off.
//
// Progressive enhancement: with JS off — or on a browser without
// <dialog> support — the revoke <form> still POSTs directly (the server
// requires a valid session regardless). With JS on, the form only
// submits after the human confirms.
//
// Served same-origin under CSP `script-src 'self'` — no inline handlers.
(function () {
  var dialog = document.getElementById('revoke-modal');
  // No <dialog> (or no showModal) → leave the forms as plain submits.
  if (!dialog || typeof dialog.showModal !== 'function') return;

  var didEl = dialog.querySelector('[data-modal-did]');
  var labelEl = dialog.querySelector('[data-modal-label]');
  var confirmBtn = dialog.querySelector('[data-modal-confirm]');
  var cancelBtn = dialog.querySelector('[data-modal-cancel]');

  // The revoke form awaiting confirmation, if any.
  var pending = null;

  function openFor(form) {
    pending = form;
    var did = form.getAttribute('data-agent-did') || '';
    var label = form.getAttribute('data-agent-label') || '';
    if (didEl) didEl.textContent = did;
    if (labelEl) {
      if (label) {
        labelEl.textContent = '“' + label + '”'; // “label”
        labelEl.hidden = false;
      } else {
        labelEl.textContent = '';
        labelEl.hidden = true;
      }
    }
    dialog.showModal();
  }

  var forms = document.querySelectorAll('form[data-revoke]');
  for (var i = 0; i < forms.length; i++) {
    forms[i].addEventListener('submit', function (e) {
      // Confirmed pass-through: openFor() never sets this; only the
      // confirm button does, right before it calls .submit().
      if (this.getAttribute('data-confirmed') === '1') return;
      e.preventDefault();
      openFor(this);
    });
  }

  if (confirmBtn) {
    confirmBtn.addEventListener('click', function () {
      if (!pending) return;
      var form = pending;
      pending = null;
      dialog.close();
      // form.submit() does not fire the submit listener, so this POSTs
      // straight to the server. The attribute is belt-and-suspenders in
      // case the submit path ever changes to requestSubmit().
      form.setAttribute('data-confirmed', '1');
      form.submit();
    });
  }
  if (cancelBtn) {
    cancelBtn.addEventListener('click', function () {
      dialog.close();
    });
  }
  // Escape / backdrop close also lands here — clear the pending ref so a
  // later confirm can't fire against a stale form.
  dialog.addEventListener('close', function () {
    pending = null;
  });
})();
