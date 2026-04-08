/* global AdminReports, AdminDirectory */
/**
 * Code.gs — Entry points: onOpen menu, onInstall, doGet, scheduledSync trigger.
 * All heavy lifting delegated to dedicated system files.
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
