/**
 * TraceLens — main script
 * Intercepts the search form submit to show the network investigation
 * animation overlay while the browser awaits the server response.
 */
document.addEventListener('DOMContentLoaded', function () {
  var form = document.querySelector('form[action="/search"]');
  if (!form) return;

  var platforms = window.TL_PLATFORMS;
  if (!platforms || !platforms.length || typeof TraceLensLoader === 'undefined') return;

  form.addEventListener('submit', function () {
    // Do NOT preventDefault — the form still POSTs normally.
    // The overlay plays while the browser awaits the Flask response.
    // When the server returns results.html the browser navigates and
    // the overlay disappears with the old DOM.
    TraceLensLoader.start(platforms);
  });
});
