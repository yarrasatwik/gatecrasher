// Review delay for protected environments on /plans. A button rendered with
// data-unlock-after="N" stays disabled for N seconds and counts down. The
// server enforces the same delay, so this file only shows it.
(function () {
  "use strict";
  var buttons = document.querySelectorAll("button[data-unlock-after]");
  Array.prototype.forEach.call(buttons, function (button) {
    var left = parseInt(button.getAttribute("data-unlock-after"), 10);
    if (!(left > 0)) { return; }
    var label = button.textContent;
    button.disabled = true;
    function tick() {
      if (left <= 0) {
        button.disabled = false;
        button.textContent = label;
        return;
      }
      button.textContent = label + " (" + left + ")";
      left -= 1;
      window.setTimeout(tick, 1000);
    }
    tick();
  });
})();
