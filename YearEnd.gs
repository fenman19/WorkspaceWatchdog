/* global AdminReports, AdminDirectory */
/**
 * YearEnd.gs — Year-End Data Reset: confirmation dialog and reset execution.
 *
 * Clears data rows (preserving headers) on Main, OUCache, Active Now, Suspicious.
 * Clears KeyIndex entirely. Resets all dedup Script Properties and lastRunISO.
 * GeoCache, Archive, Diagnostics, Settings, and triggers are preserved.
 */

function showYearEndResetDialog() {
  const html = HtmlService.createHtmlOutput(
    '<div style="font-family:Arial,sans-serif;padding:20px;background:#0f1923;color:#e8eaed;min-height:200px;">' +

    '<div style="font-size:16px;font-weight:700;color:#ef5350;margin-bottom:10px;">' +
    '&#9888; Year-End Data Reset</div>' +

    '<p style="font-size:13px;color:#ccc;margin:0 0 14px;">This will permanently clear all data rows from:<br>' +
    '<strong style="color:#8ab4f8;">Main, OUCache, Active Now, Suspicious, KeyIndex</strong></p>' +

    '<p style="font-size:13px;color:#ccc;margin:0 0 14px;">' +
    'Alert dedup keys and the sync cursor will also be reset so the next sync starts fresh.<br>' +
    '<strong style="color:#81c995;">GeoCache, Archive, Diagnostics, and all Settings are preserved.</strong></p>' +

    '<p style="font-size:13px;color:#ffaa00;margin:0 0 10px;">' +
    'This action <strong>cannot be undone.</strong> Type <strong>RESET</strong> below to confirm.</p>' +

    '<input id="confirmInput" type="text" placeholder="Type RESET here" autocomplete="off" ' +
    'style="width:100%;box-sizing:border-box;padding:8px 10px;font-size:14px;' +
    'background:#1e3a5f;color:#e8eaed;border:1px solid #3a5070;border-radius:4px;margin-bottom:14px;" />' +

    '<div style="display:flex;gap:10px;">' +
    '<button onclick="doReset()" ' +
    'style="flex:1;padding:10px;background:#ef5350;color:#fff;border:none;border-radius:4px;' +
    'font-size:13px;font-weight:700;cursor:pointer;">Reset Data</button>' +
    '<button onclick="google.script.host.close()" ' +
    'style="flex:1;padding:10px;background:#3a5070;color:#e8eaed;border:none;border-radius:4px;' +
    'font-size:13px;cursor:pointer;">Cancel</button>' +
    '</div>' +

    '<div id="status" style="margin-top:12px;font-size:12px;color:#9aa0a6;min-height:18px;"></div>' +

    '<script>' +
    'function doReset() {' +
    '  var val = document.getElementById("confirmInput").value.trim();' +
    '  if (val !== "RESET") {' +
    '    document.getElementById("status").style.color = "#ef5350";' +
    '    document.getElementById("status").textContent = "You must type RESET exactly to proceed.";' +
    '    return;' +
    '  }' +
    '  document.getElementById("status").style.color = "#9aa0a6";' +
    '  document.getElementById("status").textContent = "Working\u2026 please wait.";' +
    '  var btns = document.querySelectorAll("button");' +
    '  btns.forEach(function(b) { b.disabled = true; });' +
    '  google.script.run' +
    '    .withSuccessHandler(function(msg) {' +
    '      document.getElementById("status").style.color = "#81c995";' +
    '      document.getElementById("status").textContent = msg;' +
    '      setTimeout(function() { google.script.host.close(); }, 2500);' +
    '    })' +
    '    .withFailureHandler(function(err) {' +
    '      document.getElementById("status").style.color = "#ef5350";' +
    '      document.getElementById("status").textContent = "Error: " + err.message;' +
    '      btns.forEach(function(b) { b.disabled = false; });' +
    '    })' +
    '    .executeYearEndReset();' +
    '}' +
    '<\/script>' +
    '</div>'
  ).setWidth(460).setHeight(320);

  SpreadsheetApp.getUi().showModalDialog(html, 'Year-End Data Reset');
}

function executeYearEndReset() {
  _applyRuntimeConfig_();

  var ss = SpreadsheetApp.getActive();
  var now = new Date();
  var actor = '';
  try { actor = Session.getEffectiveUser().getEmail(); } catch (e) {}

  var targetSheets = [
    { key: CONFIG.MAIN,       label: 'Main'      },
    { key: CONFIG.OU_CACHE,   label: 'OUCache'   },
    { key: CONFIG.ACTIVE,     label: 'Active Now' },
    { key: CONFIG.SUSPICIOUS, label: 'Suspicious' }
  ];

  var sheetsCleared = [];
  var totalRowsCleared = 0;

  targetSheets.forEach(function(def) {
    var sh = ss.getSheetByName(def.key);
    if (!sh) return;
    var lastRow = sh.getLastRow();
    if (lastRow > 1) {
      var dataRows = lastRow - 1;
      sh.getRange(2, 1, dataRows, sh.getLastColumn()).clearContent();
      sheetsCleared.push(def.label + ' (' + dataRows + ' rows)');
      totalRowsCleared += dataRows;
    } else {
      sheetsCleared.push(def.label + ' (already empty)');
    }
  });

  var shKI = ss.getSheetByName(KEY_INDEX_SHEET);
  if (shKI) { if (shKI.getLastRow() > 0) shKI.clearContents(); }
  __KEY_INDEX = null;

  _resetAllCaches_();

  var p = PropertiesService.getScriptProperties();
  var allKeys = p.getKeys();
  var purgedCount = 0;
  allKeys.forEach(function(k) {
    if (k.startsWith('ww_alert_') || k.startsWith('ww_alerted_') ||
        k.startsWith('ww_chat_digest_') || k.startsWith('ww_weekly_report_')) {
      p.deleteProperty(k);
      purgedCount++;
    }
  });

  p.deleteProperty('lastRunISO');

  var notes =
    'YEAR-END RESET by ' + (actor || 'unknown') +
    ' | Sheets cleared: ' + sheetsCleared.join(', ') +
    ' | Total rows removed: ' + totalRowsCleared +
    ' | Alert/dedup keys purged: ' + purgedCount +
    ' | lastRunISO reset';

  try { _logDiagnostics('yearEndReset', now, new Date(), 0, 0, notes); } catch (e) {}

  ss.toast(
    'Year-end reset complete. ' + totalRowsCleared + ' rows cleared across ' + targetSheets.length + ' sheets.',
    'Workspace Watchdog', 8
  );

  return 'Reset complete — ' + totalRowsCleared + ' rows cleared. The dialog will close.';
}
