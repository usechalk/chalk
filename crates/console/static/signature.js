// Signature pad for the circulation desk (SS-1, DESIGN_SYSTEM §5.3 spirit:
// progressive enhancement — without JS the checkout form still submits, just
// without a signature).
//
// One canvas per [data-signature-pad]. Pointer events cover mouse, touch and
// stylus in one API — the common case is a student signing on the Chromebook
// they are being handed, flipped around at the desk. On submit, a non-empty
// pad serializes to a PNG data URL in the paired hidden input.
(function () {
  'use strict';

  document.querySelectorAll('[data-signature-pad]').forEach(function (wrap) {
    var canvas = wrap.querySelector('canvas');
    var input = wrap.querySelector('input[type="hidden"]');
    var clear = wrap.querySelector('[data-signature-clear]');
    if (!canvas || !input) return;

    // Draw at device-pixel resolution so the stored PNG is not blurry on
    // high-DPI screens, while the CSS size stays put.
    var scale = window.devicePixelRatio || 1;
    var cssWidth = canvas.clientWidth || 320;
    var cssHeight = canvas.clientHeight || 120;
    canvas.width = cssWidth * scale;
    canvas.height = cssHeight * scale;
    var ctx = canvas.getContext('2d');
    ctx.scale(scale, scale);
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#1e1b4b';

    var drawing = false;
    var dirty = false;

    function pos(evt) {
      var rect = canvas.getBoundingClientRect();
      return { x: evt.clientX - rect.left, y: evt.clientY - rect.top };
    }

    canvas.addEventListener('pointerdown', function (evt) {
      drawing = true;
      dirty = true;
      canvas.setPointerCapture(evt.pointerId);
      var p = pos(evt);
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      evt.preventDefault();
    });
    canvas.addEventListener('pointermove', function (evt) {
      if (!drawing) return;
      var p = pos(evt);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      evt.preventDefault();
    });
    ['pointerup', 'pointercancel'].forEach(function (name) {
      canvas.addEventListener(name, function () {
        drawing = false;
      });
    });

    if (clear) {
      clear.addEventListener('click', function () {
        ctx.clearRect(0, 0, cssWidth, cssHeight);
        dirty = false;
        input.value = '';
      });
    }

    var form = wrap.closest('form');
    if (form) {
      form.addEventListener('submit', function () {
        // An untouched pad submits nothing — the field is optional and the
        // server treats empty as "no signature captured".
        input.value = dirty ? canvas.toDataURL('image/png') : '';
      });
    }
  });
})();
