// Live alerts for /watch. Server-sent "alert" events carry a rendered,
// already-escaped <li>; this file only inserts it. No inline script is
// needed anywhere, so the CSP can stay strict.
(function () {
  "use strict";
  var list = document.getElementById("alert-list");
  var text = document.getElementById("stream-text");
  var status = document.getElementById("stream-status");
  if (!list || !text || !window.EventSource) {
    if (text) { text.textContent = "Live updates are not supported in this browser. Reload to refresh."; }
    return;
  }
  function setStatus(live, msg) {
    text.textContent = msg;
    status.classList.toggle("is-live", live);
  }
  var source = new EventSource("/watch/stream");
  source.onopen = function () { setStatus(true, "Live: listening for changes"); };
  source.onerror = function () { setStatus(false, "Reconnecting to the live feed..."); };
  source.addEventListener("alert", function (event) {
    var holder = document.createElement("template");
    holder.innerHTML = event.data;
    var item = holder.content.firstElementChild;
    if (!item || (item.id && document.getElementById(item.id))) { return; }
    var empty = document.getElementById("no-alerts");
    if (empty) { empty.hidden = true; }
    list.insertBefore(item, list.firstChild);
  });
  window.addEventListener("pagehide", function () { source.close(); });
})();
