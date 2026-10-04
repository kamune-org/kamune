// Applies the system's dark theme before the app loads, so that the page
// does not flash light. It is a file of its own, rather than an inline
// script, as the page's Content Security Policy allows no inline script.
(function () {
  if (matchMedia('(prefers-color-scheme:dark)').matches)
    document.documentElement.classList.add('dark');
})();
