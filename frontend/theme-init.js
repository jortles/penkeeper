// Runs before the stylesheet loads, so the saved theme and font size apply
// to the first paint (no flash of the dark theme or default size). It is a
// separate file because the Content-Security-Policy allows no inline scripts.
(function () {
  var light = false, fs = 13;
  try {
    light = localStorage.getItem('theme') === 'light';
    fs = parseInt(localStorage.getItem('pk_font_size') || '13', 10) || 13;
  } catch (e) {}
  var h = document.documentElement;
  h.style.colorScheme = light ? 'light' : 'dark';
  h.style.background = light ? '#f0f2f7' : '#282c34';
  h.style.color = light ? '#1a1d23' : '#abb2bf';
  h.style.zoom = fs / 13;
})();
