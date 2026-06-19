/* global AdminReports, AdminDirectory */
/**
/* global AdminReports, AdminDirectory */
/**
 * Workspace Watchdog v3.5.3
 * Code.gs — Entry points only: onOpen menu, onInstall, doGet, scheduledSync trigger.
 * All heavy lifting delegated to dedicated system files:
 *   Utils.gs      — CONFIG, constants, headers, cache indexes, shared helpers
 *   Setup.gs      — Installation, Setup Wizard, Settings Panel
 *   Sync.gs       — Core sync engine, fetch, trim, backfill, diagnostics
 *   Geo.gs        — Geolocation, GeoCache, IP reputation
 *   OrgUnit.gs    — OU cache, bulk Directory load, OU filter
 *   Detection.gs  — Active Now, Suspicious detection, risk scoring
 *   Alerts.gs     — Google Chat alerts, whitelist, dedup
 *   Reports.gs    — Daily digest, weekly report, on-demand reports
 *   MapData.gs    — Live map data feeds
 *   Licensing.gs  — Version checking, auto-updater
 *   Archive.gs    — Archive pruning
 *   YearEnd.gs    — Year-End Data Reset
 *   Refactored from monolithic Code.gs (5,526 lines) into 13 focused files.
 *   Fixed OU cache sync issue causing slow OU loading on large domains.
 *   Fixed duplicate _loadOUMap_ causing slow GeoCache loading.
 *   Code.gs — Entry points: onOpen menu, onInstall, doGet, scheduledSync trigger.
 *   All heavy lifting delegated to dedicated system files.
 */

function onOpen() {
  _applyRuntimeConfig_();

  SpreadsheetApp.getUi()
    .createMenu('Workspace Watchdog')
    .addItem('Open Settings',        'showSettingsPanel')
    .addItem('Check for Updates',    'showUpdatesPanel')
    .addItem('Open Live Map',        'showLiveMap')
    .addItem('Full Screen Map URL',  'showFullscreenMapUrl')
    .addSeparator()
    .addItem('Run Sync Now',         'scheduledSync')
    .addItem('Run First Sync Only',  'runFirstSyncOnly')
    .addSeparator()
    .addSubMenu(SpreadsheetApp.getUi().createMenu('Advanced')
      .addItem('Rebuild Active Now (CONFIG)', 'rebuildActiveNow')
      .addItem('Rebuild Active Now (30m)',    'rebuildActiveNow30')
      .addItem('Rebuild Active Now (60m)',    'rebuildActiveNow60')
      .addItem('Run Cache Warmup',            'cacheWarmup')
      .addItem('Fix ActiveNow from OU Cache', 'fixActiveNow_OU_FromCache')
      .addItem('Bulk Load All OUs Now',       'bulkLoadAllOUsMenu')
      .addItem('Rebuild Key Index',           'rebuildKeyIndex')
      .addItem('Migrate Suspicious Sheet',    'migrateSuspiciousSheet')
      .addItem('Fill Blank Geo in Main',      'fillBlankGeoInMain')
      .addItem('Trim Setup Sheet',            'trimSetupSheetMenu')
      .addItem('Clean Up Alert Keys',         'cleanupAlertKeysNow')
      .addItem('Purge All Alert Keys',        'purgeAlertKeys')
      .addSeparator()
      .addItem('🗑️ Year-End Data Reset...',   'showYearEndResetDialog')
    )
    .addSubMenu(SpreadsheetApp.getUi().createMenu('Diagnostics & Testing')
      .addItem('Test Chat Alert',        'testChatAlert')
      .addItem('Send Digest Now',        'sendDailyDigestNow')
      .addItem('Send Weekly Report Now', 'sendWeeklyReportNow')
      .addItem('Trim Diagnostics Sheet', 'trimDiagnosticsSheetMenu')
      .addItem('Show Setup Status',      'showSetupStatus')
      .addItem('Reset Install State',    'resetInstallState')
    )
    .addSeparator()
    .addItem('Setup Wizard', 'showSetupWizard')
    .addToUi();

  _showLicenseBannerIfNeeded_();
}

// Shows a license banner (toast) or, for full shutdown, a persistent popup
// dialog limited to once per calendar day. Never throws — a license-state
// problem should never prevent the menu itself from loading.
function _showLicenseBannerIfNeeded_() {
  try {
    _maybeRevalidateLicense_();
    var state = _getLicenseState_();
    var ss = SpreadsheetApp.getActive();
    var today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');

    switch (state.phase) {
      case 'warn15':
        ss.toast('Your Workspace Watchdog license expires in ' + state.daysUntil +
          ' days (' + state.expiresOn + '). Visit workspacewatchdog.com to renew.',
          'License Expiring Soon', 8);
        break;
      case 'warn7':
        ss.toast('Your Workspace Watchdog license expires in ' + state.daysUntil +
          ' day' + (state.daysUntil === 1 ? '' : 's') + ' (' + state.expiresOn + '). Visit workspacewatchdog.com to renew.',
          '⚠ License Expiring Soon', 10);
        break;
      case 'warn1':
        ss.toast('Your Workspace Watchdog license expires ' +
          (state.daysUntil === 0 ? 'today' : 'tomorrow') + ' (' + state.expiresOn + '). Visit workspacewatchdog.com to renew.',
          '⚠ License Expires ' + (state.daysUntil === 0 ? 'Today' : 'Tomorrow'), 15);
        break;
      case 'mapLocked':
        ss.toast('Your license expired on ' + state.expiresOn + '. The Live Map is disabled until renewed. ' +
          'Full monitoring will stop if not renewed soon. Visit workspacewatchdog.com to renew.',
          '⚠ License Expired — Map Disabled', 20);
        break;
      case 'shutdown': {
        var p = PropertiesService.getScriptProperties();
        var lastPopup = p.getProperty(LICENSE_PROPS.LAST_POPUP);
        if (lastPopup !== today) {
          p.setProperty(LICENSE_PROPS.LAST_POPUP, today);
          SpreadsheetApp.getUi().alert(
            'Workspace Watchdog — License Expired',
            'Your license expired on ' + state.expiresOn + ' and the grace period has ended.\n\n' +
            'Monitoring, alerts, and the Live Map are now disabled.\n\n' +
            'Open the Setup Wizard and enter a renewed license token to restore service.\n\n' +
            'Visit workspacewatchdog.com to renew, or contact support@workspacewatchdog.com.',
            SpreadsheetApp.getUi().ButtonSet.OK
          );
        }
        break;
      }
      default:
        // 'active', 'lifetime', 'unlicensed' — nothing to show
        break;
    }
  } catch (e) {
    // Never let a license-check problem block the menu from loading.
  }
}

function install() {
  installWorkspaceWatchdog();
}

function onInstall() {
  onOpen();
}

function doGet(e) {
  try {
    _requireAllowedUser_();
    const tab = _getParam_(e, 'tab') || 'livemap';

    if (tab === 'livemap' || tab === '') {
      const state = _getLicenseState_();
      if (state.phase === 'mapLocked' || state.phase === 'shutdown') {
        return _licenseLockedMapPage_(state);
      }
      return HtmlService.createHtmlOutputFromFile('LiveMap')
        .setTitle('Workspace Watchdog - Live Map')
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
    }

    const ss = SpreadsheetApp.getActive();
    const sh = ss.getSheetByName(tab);
    if (!sh) return _json_({ ok: false, message: 'Unknown tab: ' + tab });

    const lastRow = sh.getLastRow();
    const lastCol = sh.getLastColumn();
    if (lastRow < 2 || lastCol < 1) return _json_({ ok: true, tab, rowCount: 0, rows: [] });

    const headers = sh.getRange(1, 1, 1, lastCol).getValues()[0].map(String);
    const values  = sh.getRange(2, 1, lastRow - 1, lastCol).getValues();
    const rows    = values.map(r => {
      const obj = {};
      for (let i = 0; i < headers.length; i++) { obj[headers[i]] = r[i]; }
      return obj;
    });

    return _json_({ ok: true, tab, rowCount: rows.length, rows });
  } catch (err) {
    return _json_({ ok: false, message: (err && err.message) ? err.message : String(err) });
  }
}

function _getParam_(e, name) {
  if (!e || !e.parameter) return "";
  return e.parameter[name] || "";
}

function _json_(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// Branded standalone page shown in place of the Live Map once a license has
// expired (mapLocked or shutdown phase). Matches the dark WW theme.
function _licenseLockedMapPage_(state) {
  var heading = state.phase === 'shutdown'
    ? 'License Expired — Monitoring Disabled'
    : 'License Expired — Map Disabled';
  var message = state.phase === 'shutdown'
    ? 'Your license expired on ' + state.expiresOn + ' and the grace period has ended. ' +
      'Monitoring, alerts, and the Live Map are disabled until a renewed license is activated.'
    : 'Your license expired on ' + state.expiresOn + '. The Live Map is disabled until renewed. ' +
      'Monitoring and alerts are still running for now.';

  var html =
    '<!DOCTYPE html><html><head><meta charset="utf-8">' +
    '<style>' +
    'body{margin:0;background:#050810;color:#c8d8e8;font-family:Arial,sans-serif;' +
    'display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;}' +
    '.box{max-width:480px;padding:40px;border:1px solid #1e3a5f;border-radius:8px;background:#0b0f1a;}' +
    'h1{color:#ff4444;font-size:20px;letter-spacing:1px;margin:0 0 16px;}' +
    'p{color:#8ab4d4;font-size:14px;line-height:1.6;margin:0 0 20px;}' +
    'a{color:#00c8ff;font-weight:bold;text-decoration:none;}' +
    '</style></head><body>' +
    '<div class="box">' +
    '<h1>' + heading + '</h1>' +
    '<p>' + message + '</p>' +
    '<p><a href="https://workspacewatchdog.com" target="_blank">Visit workspacewatchdog.com to renew</a></p>' +
    '</div></body></html>';

  return HtmlService.createHtmlOutput(html)
    .setTitle('Workspace Watchdog - License Expired')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
