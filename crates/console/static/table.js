/*
 * table.js — keyboard and selection behaviour for the dense data table
 * (DESIGN_SYSTEM.md §5.3, APG Grid pattern).
 *
 * Progressive enhancement, strictly. Without this file the table is still a
 * sortable, filterable, paginated, form-wrapped table with working checkboxes;
 * everything here is roving-tabindex navigation, shift-click ranges, and
 * keeping the bulk bar's count honest about which selection mode is in effect.
 *
 * The one behaviour that is not cosmetic: switching between filter scope and
 * picked rows. The table defaults to filter scope — "400 devices match this
 * filter" — because a spreadsheet user's instinct is that filtering *is*
 * selecting. Ticking a checkbox is an explicit narrowing to the picked rows,
 * and the bar has to say so, in words, every time.
 *
 * Re-runs after every HTMX swap, because the region is replaced wholesale.
 */
(function () {
  "use strict";

  var SINGULAR = "row";
  var PLURAL = "rows";

  function announce(message) {
    var bus = document.getElementById("announcer");
    if (bus) {
      bus.textContent = message;
    }
  }

  function rowsOf(table) {
    return Array.prototype.slice.call(table.querySelectorAll("tbody tr"));
  }

  function checkboxOf(row) {
    return row.querySelector("[data-row-check]");
  }

  function pickedIn(table) {
    return rowsOf(table).filter(function (row) {
      var box = checkboxOf(row);
      return box && box.checked;
    });
  }

  /*
   * The bulk bar is the safety surface, so its two modes never share a
   * sentence. Filter scope keeps the server-rendered text (which names the
   * filter and any rows beyond this page). Picked mode replaces it with a
   * count that says "on this page", because that is exactly what it is.
   */
  function refreshBulkBar(region) {
    var bar = region.querySelector("[data-bulkbar]");
    var table = region.querySelector("[data-grid]");
    if (!bar || !table) return;

    var singular = bar.getAttribute("data-singular") || SINGULAR;
    var plural = bar.getAttribute("data-plural") || PLURAL;
    var count = pickedIn(table).length;
    var output = bar.querySelector("[data-bulk-count]");
    var beyond = bar.querySelector("[data-bulk-beyond]");
    var mode = bar.querySelector("[data-selection-mode]");
    var clear = bar.querySelector("[data-bulk-clear]");

    if (count > 0) {
      bar.setAttribute("data-mode", "picked");
      if (mode) mode.value = "picked";
      if (output) {
        output.textContent =
          count + " " + (count === 1 ? singular : plural) + " picked on this page";
      }
      if (beyond) beyond.hidden = true;
      if (clear) clear.hidden = false;
    } else {
      bar.setAttribute("data-mode", "matching");
      if (mode) mode.value = "matching";
      if (output) output.textContent = output.getAttribute("data-scope-text") || output.textContent;
      if (beyond) beyond.hidden = false;
      if (clear) clear.hidden = true;
    }

    var all = region.querySelector("[data-check-all]");
    if (all) {
      var total = rowsOf(table).length;
      all.checked = total > 0 && count === total;
      all.indeterminate = count > 0 && count < total;
    }
  }

  function setChecked(row, checked) {
    var box = checkboxOf(row);
    if (!box) return;
    box.checked = checked;
    row.classList.toggle("is-picked", checked);
  }

  /* Roving tabindex: exactly one row is in the tab order at a time, so Tab
     leaves the grid rather than walking every row of a 250-row page. */
  function focusRow(table, row) {
    rowsOf(table).forEach(function (r) {
      r.tabIndex = r === row ? 0 : -1;
    });
    if (row) row.focus();
  }

  function initRegion(region) {
    var table = region.querySelector("[data-grid]");
    if (!table || table.hasAttribute("data-grid-ready")) return;
    table.setAttribute("data-grid-ready", "true");

    var rows = rowsOf(table);
    rows.forEach(function (row, index) {
      row.tabIndex = index === 0 ? 0 : -1;
    });

    // Preserve the server's filter-scope sentence so leaving picked mode can
    // restore it verbatim rather than reconstructing it in two places.
    var output = region.querySelector("[data-bulk-count]");
    if (output && !output.getAttribute("data-scope-text")) {
      output.setAttribute("data-scope-text", output.textContent.trim());
    }

    var anchorIndex = null;

    table.addEventListener("change", function (event) {
      var box = event.target.closest("[data-row-check]");
      if (!box) return;
      var row = box.closest("tr");
      if (row) row.classList.toggle("is-picked", box.checked);
      refreshBulkBar(region);
    });

    // Shift-click range select. `click` rather than `change` so the anchor is
    // recorded even when the click lands on an already-checked box.
    //
    // The same handler moves grid focus to the clicked row. Clicking a `<td>`
    // does NOT focus its `tabindex`-bearing `<tr>` — the browser sends focus to
    // `<body>` instead — so without this the roving tabindex only ever tracks
    // the keyboard, and a technician who clicks a row then presses ↓ scrolls
    // the document rather than moving down the grid. Done on `click` rather
    // than `mousedown` so text selection inside a cell still works: copying a
    // serial number out of the table is a thing people do all day.
    table.addEventListener("click", function (event) {
      var box = event.target.closest("[data-row-check]");
      if (!box) {
        var clickedRow = event.target.closest("tbody tr");
        // Links and controls own their own focus; stealing it would break
        // "click the student, land on the student".
        if (clickedRow && !event.target.closest("a[href], button, input, select")) {
          focusRow(table, clickedRow);
        }
        return;
      }
      var current = rowsOf(table).indexOf(box.closest("tr"));
      if (event.shiftKey && anchorIndex !== null) {
        var from = Math.min(anchorIndex, current);
        var to = Math.max(anchorIndex, current);
        var all = rowsOf(table);
        for (var i = from; i <= to; i++) {
          setChecked(all[i], box.checked);
        }
        refreshBulkBar(region);
      }
      anchorIndex = current;
    });

    table.addEventListener("keydown", function (event) {
      var row = event.target.closest("tbody tr");
      if (!row || !table.contains(row)) return;
      var all = rowsOf(table);
      var index = all.indexOf(row);

      switch (event.key) {
        case "ArrowDown":
          event.preventDefault();
          if (event.shiftKey) setChecked(all[index], true);
          focusRow(table, all[Math.min(index + 1, all.length - 1)]);
          if (event.shiftKey) {
            setChecked(all[Math.min(index + 1, all.length - 1)], true);
            refreshBulkBar(region);
          }
          break;
        case "ArrowUp":
          event.preventDefault();
          if (event.shiftKey) setChecked(all[index], true);
          focusRow(table, all[Math.max(index - 1, 0)]);
          if (event.shiftKey) {
            setChecked(all[Math.max(index - 1, 0)], true);
            refreshBulkBar(region);
          }
          break;
        case "Home":
          event.preventDefault();
          focusRow(table, all[0]);
          break;
        case "End":
          event.preventDefault();
          focusRow(table, all[all.length - 1]);
          break;
        case " ":
        case "x":
        case "X": {
          // Space on a control is the control's own; only claim it on the row.
          if (event.target !== row) return;
          event.preventDefault();
          var box = checkboxOf(row);
          setChecked(row, !(box && box.checked));
          anchorIndex = index;
          refreshBulkBar(region);
          break;
        }
        case "Enter": {
          if (event.target !== row) return;
          var link = row.querySelector("a[href]");
          if (link) {
            event.preventDefault();
            link.click();
          }
          break;
        }
        case "a":
        case "A":
          if (!(event.ctrlKey || event.metaKey)) return;
          event.preventDefault();
          all.forEach(function (r) {
            setChecked(r, true);
          });
          refreshBulkBar(region);
          announce(all.length + " rows picked on this page");
          break;
        case "Escape":
          all.forEach(function (r) {
            setChecked(r, false);
          });
          refreshBulkBar(region);
          announce("Selection cleared");
          break;
        default:
          return;
      }
    });

    var all = region.querySelector("[data-check-all]");
    if (all) {
      all.addEventListener("change", function () {
        rowsOf(table).forEach(function (r) {
          setChecked(r, all.checked);
        });
        refreshBulkBar(region);
      });
    }

    var clear = region.querySelector("[data-bulk-clear]");
    if (clear) {
      clear.addEventListener("click", function () {
        rowsOf(table).forEach(function (r) {
          setChecked(r, false);
        });
        refreshBulkBar(region);
        announce("Selection cleared");
      });
    }

    refreshBulkBar(region);
  }

  function initAll() {
    Array.prototype.slice
      .call(document.querySelectorAll("[data-table-region]"))
      .forEach(initRegion);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll);
  } else {
    initAll();
  }

  // The region is swapped wholesale, so listeners and the roving tabindex have
  // to be re-established on the new nodes.
  document.body.addEventListener("htmx:afterSwap", initAll);
})();
