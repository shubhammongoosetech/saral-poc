(function() {
  try {
    var theme = localStorage.getItem('saral-theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.colorScheme = theme;
  } catch (e) {}
})();
