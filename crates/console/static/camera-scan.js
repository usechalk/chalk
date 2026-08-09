// Phone-camera scanning for the physical-inventory surfaces (GP-1).
//
// Progressive enhancement in the signature-pad tradition: the page works
// unchanged with a keyboard-wedge scanner or a typed code, and this file only
// adds a "Use camera" button when the browser can actually deliver — a secure
// context, getUserMedia, and the native BarcodeDetector (Chrome on ChromeOS,
// Android, desktop). Where BarcodeDetector is missing (notably iOS Safari)
// the button never appears and nothing else changes; there is deliberately no
// bundled decoder library, per the no-external-code rule.
//
// The walk flow: each scan submits the form, the page round-trips, and the
// camera re-opens itself (a sessionStorage flag survives the reload), so an
// audit is point, point, point — the phone equivalent of the wedge scanner's
// scan, scan, scan.
(function () {
  'use strict';

  var input = document.querySelector('input[data-camera-scan]');
  if (
    !input ||
    !input.form ||
    !('BarcodeDetector' in window) ||
    !navigator.mediaDevices ||
    !navigator.mediaDevices.getUserMedia
  ) {
    return;
  }

  // The formats a district actually sticks on hardware: our own QR labels,
  // vendor Code 128/39 asset tags, and retail EAN/UPC on boxed accessories.
  // Construction can throw on an unsupported list, so fall back to the
  // browser's default set rather than losing the feature.
  var detector;
  try {
    detector = new window.BarcodeDetector({
      formats: ['qr_code', 'code_128', 'code_39', 'ean_13', 'upc_a', 'itf', 'data_matrix'],
    });
  } catch (_) {
    try {
      detector = new window.BarcodeDetector();
    } catch (_) {
      return;
    }
  }

  var REOPEN_KEY = 'chalkCameraScan';
  var overlay = null;
  var stream = null;
  var timer = null;

  var button = document.createElement('button');
  button.type = 'button';
  button.className = 'btn-secondary';
  button.textContent = 'Use camera';
  button.setAttribute('data-camera-open', '');
  input.insertAdjacentElement('afterend', button);
  button.addEventListener('click', function () {
    sessionStorage.setItem(REOPEN_KEY, 'on');
    open();
  });

  function close(forgetReopen) {
    if (forgetReopen) {
      sessionStorage.removeItem(REOPEN_KEY);
    }
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    if (stream) {
      stream.getTracks().forEach(function (t) {
        t.stop();
      });
      stream = null;
    }
    if (overlay) {
      overlay.remove();
      overlay = null;
    }
  }

  function open() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'camera-overlay';
    overlay.innerHTML =
      '<div class="camera-overlay__bar">' +
      '<span>Point at a label</span>' +
      '<button type="button" class="btn-secondary" data-camera-close>Close</button>' +
      '</div><video playsinline muted></video>';
    document.body.appendChild(overlay);
    var video = overlay.querySelector('video');
    overlay
      .querySelector('[data-camera-close]')
      .addEventListener('click', function () {
        // An explicit close means "back to the keyboard": stop re-opening
        // after the next submit, and put the cursor where the wedge types.
        close(true);
        input.focus();
      });

    navigator.mediaDevices
      // The rear camera, ideally: labels are on the desk, not the operator.
      .getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      .then(function (s) {
        stream = s;
        video.srcObject = s;
        return video.play();
      })
      .then(function () {
        var lastCode = '';
        var lastAt = 0;
        timer = setInterval(function () {
          if (!video.videoWidth) return;
          detector
            .detect(video)
            .then(function (codes) {
              if (!codes.length) return;
              var code = codes[0].rawValue.trim();
              var now = Date.now();
              // The same label sits in frame for many detect() ticks; only a
              // new code, or the same one after a real pause, counts.
              if (!code || (code === lastCode && now - lastAt < 3000)) return;
              lastCode = code;
              lastAt = now;
              if (navigator.vibrate) navigator.vibrate(50);
              input.value = code;
              close(false);
              input.form.requestSubmit();
            })
            .catch(function () {
              /* a mid-teardown frame; the next tick will see a live one */
            });
        }, 150);
      })
      .catch(function () {
        // Denied or no camera: drop back to the keyboard path for good.
        close(true);
        input.focus();
      });
  }

  // Continue the walk: if the camera was open when the last scan submitted,
  // re-open it as soon as the round-tripped page is ready.
  if (sessionStorage.getItem(REOPEN_KEY) === 'on') {
    open();
  }
})();
