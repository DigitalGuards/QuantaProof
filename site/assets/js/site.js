/* QuantaStark site script. The only behaviour on the page: the bridge preview
   is wired to nothing, so any attempt to use it shows a short "not connected"
   status near the pointer (or under the focused button for keyboard users).
   No network calls, no dependencies. */
(function () {
  'use strict';

  var tip = document.getElementById('net-tip');
  var panels = document.querySelectorAll('[data-bridge-mock]');
  if (!tip || panels.length === 0) return;

  var MESSAGE = 'Not connected to a network yet: the bridge is a preview.';
  var hideTimer = null;

  function hide() {
    tip.classList.remove('is-visible');
  }

  function show(x, y) {
    // Clearing before setting makes assistive technology re-announce the status.
    tip.textContent = '';
    tip.textContent = MESSAGE;
    tip.classList.add('is-visible');
    var width = tip.offsetWidth;
    var height = tip.offsetHeight;
    var left = Math.min(Math.max(8, x + 12), window.innerWidth - width - 8);
    var top = y + 16;
    if (top + height > window.innerHeight - 8) top = Math.max(8, y - height - 12);
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hide, 2600);
  }

  function pointFor(event) {
    // Keyboard activation reports no coordinates; anchor under the control.
    if (event.clientX || event.clientY) return { x: event.clientX, y: event.clientY };
    var rect = event.target.getBoundingClientRect();
    return { x: rect.left, y: rect.bottom - 8 };
  }

  Array.prototype.forEach.call(panels, function (panel) {
    panel.addEventListener('click', function (event) {
      var control = event.target.closest('input, textarea, button, label, .field');
      if (!control) return;
      event.preventDefault();
      var point = pointFor(event);
      show(point.x, point.y);
    });
    panel.addEventListener('submit', function (event) {
      event.preventDefault();
    });
  });
})();
