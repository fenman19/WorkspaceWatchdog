/* global AdminReports, AdminDirectory */
/**
 * Setup.gs — Installation, Setup Wizard, Settings Panel, and setup sheet management.
 */

function installWorkspaceWatchdog() {
  _applyRuntimeConfig_();
  _ensureAllSheets();

  const ss = SpreadsheetApp.getActive();
  _ensureHeaders(ss.getSheetByName(CONFIG.MAIN), MAIN_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.GEOCACHE), GEO_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.OU_CACHE), OU_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.ACTIVE), ACTIVE_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.SUSPICIOUS), SUSP_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.DIAG), DIAG_HEADERS);
  _ensureHeaders(ss.getSheetByName(CONFIG.ARCHIVE), MAIN_HEADERS);

  _ensureSetupSheet_();
  _saveSetupSummaryToSheet_();

  _deleteMyTriggers_();
  ScriptApp.newTrigger('scheduledSync').timeBased().everyMinutes(CONFIG.SYNC_EVERY_MINUTES).create();
  ScriptApp.newTrigger('weeklyReset').timeBased().atHour(0).everyDays(1).create();
  ScriptApp.newTrigger('cacheWarmup').timeBased().everyMinutes(CONFIG.CACHE_WARMUP_INTERVAL_MINUTES).create();
  ScriptApp.newTrigger('dailyDigest').timeBased().everyHours(1).create();
  ScriptApp.newTrigger('weeklyReport').timeBased().everyHours(1).create();

  PropertiesService.getScriptProperties().deleteProperty('lastRunISO');

  PropertiesService.getScriptProperties().setProperties({
    INSTALL_COMPLETE: 'true',
    INSTALL_VERSION: WW_MONITOR_VERSION,
    INSTALL_TIMESTAMP: new Date().toISOString()
  }, true);

  if (CONFIG.BULK_OU_LOAD) {
    SpreadsheetApp.getActive().toast('Pre-loading OU cache...', 'Install', 5);
    _bulkLoadAllOUs_(SpreadsheetApp.getActive().getSheetByName(CONFIG.OU_CACHE));
  }
  rebuildKeyIndex();
  SpreadsheetApp.getActive().toast('Workspace Watchdog installed. Running first sync...', 'Install', 5);
  scheduledSync();
}

function fastInstallWorkspaceWatchdog(seedMinutes) {
  _applyRuntimeConfig_();

  const p = PropertiesService.getScriptProperties();
  const originalLookback =
    p.getProperty('LOOKBACK_MINUTES_ON_FIRST_RUN') ||
    String(CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN || 1440);

  const requested = Number(seedMinutes);
  const fastLookbackMinutes = (isFinite(requested) && requested > 0)
    ? Math.max(5, Math.round(requested))
    : Math.max(5, Math.round(CONFIG.FAST_INSTALL_LOOKBACK_MINUTES || 120));

  try {
    p.setProperty('LOOKBACK_MINUTES_ON_FIRST_RUN', String(fastLookbackMinutes));
    _applyRuntimeConfig_();

    _ensureAllSheets();

    const ss = SpreadsheetApp.getActive();
    _ensureHeaders(ss.getSheetByName(CONFIG.MAIN), MAIN_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.GEOCACHE), GEO_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.OU_CACHE), OU_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.ACTIVE), ACTIVE_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.SUSPICIOUS), SUSP_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.DIAG), DIAG_HEADERS);
    _ensureHeaders(ss.getSheetByName(CONFIG.ARCHIVE), MAIN_HEADERS);

    _ensureSetupSheet_();
    _saveSetupSummaryToSheet_();

    _deleteMyTriggers_();
    ScriptApp.newTrigger('scheduledSync').timeBased().everyMinutes(CONFIG.SYNC_EVERY_MINUTES).create();
    ScriptApp.newTrigger('weeklyReset').timeBased().atHour(0).everyDays(1).create();
    ScriptApp.newTrigger('cacheWarmup').timeBased().everyMinutes(CONFIG.CACHE_WARMUP_INTERVAL_MINUTES).create();
    ScriptApp.newTrigger('dailyDigest').timeBased().everyHours(1).create();
    ScriptApp.newTrigger('weeklyReport').timeBased().everyHours(1).create();

    p.setProperties({
      INSTALL_COMPLETE: 'true',
      INSTALL_VERSION: WW_MONITOR_VERSION,
      INSTALL_TIMESTAMP: new Date().toISOString()
    }, true);

    p.deleteProperty('lastRunISO');

    if (CONFIG.BULK_OU_LOAD) {
      SpreadsheetApp.getActive().toast('Pre-loading OU cache...', 'Workspace Watchdog', 5);
      _bulkLoadAllOUs_(SpreadsheetApp.getActive().getSheetByName(CONFIG.OU_CACHE));
    }
    rebuildKeyIndex();

    SpreadsheetApp.getActive().toast(
      'Fast Install complete. Running ' + fastLookbackMinutes + ' minute seed sync...',
      'Workspace Watchdog', 5
    );
    scheduledSync();
    SpreadsheetApp.getActive().toast('Fast Install finished. Normal settings restored.', 'Workspace Watchdog', 5);
  } finally {
    p.setProperty('LOOKBACK_MINUTES_ON_FIRST_RUN', String(originalLookback));
    _applyRuntimeConfig_();
    _saveSetupSummaryToSheet_();
  }
}

function runFirstSyncOnly() {
  _applyRuntimeConfig_();
  scheduledSync();
}

function showSetupWizard() {
  const html = HtmlService.createHtmlOutputFromFile('SetupWizard')
    .setTitle('Workspace Watchdog — Setup Wizard')
    .setWidth(680)
    .setHeight(780);
  SpreadsheetApp.getUi().showModalDialog(html, 'Workspace Watchdog — Setup Wizard');
}

function showSettingsPanel() {
  const html = HtmlService.createHtmlOutputFromFile('Settings')
    .setTitle('Workspace Watchdog — Settings')
    .setWidth(680)
    .setHeight(820);
  SpreadsheetApp.getUi().showModalDialog(html, 'Workspace Watchdog — Settings');
}

function showSetupStatus() {
  const s = getSetupStatus();
  const lines = [
    'Installed: ' + (s.installed ? 'Yes' : 'No'),
    'Version: ' + (s.installVersion || '(none)'),
    'Last install: ' + (s.installTimestamp || '(none)'),
    'Triggers: ' + s.triggerCount,
    'Missing sheets: ' + (s.missingSheets.length ? s.missingSheets.join(', ') : 'None'),
    'Last run cursor: ' + (s.lastRunISO || '(none)')
  ];
  SpreadsheetApp.getUi().alert('Workspace Watchdog Status', lines.join('\\n'), SpreadsheetApp.getUi().ButtonSet.OK);
}

function getSetupStatus() {
  _applyRuntimeConfig_();
  const p = PropertiesService.getScriptProperties();
  const ss = SpreadsheetApp.getActive();
  const required = [CONFIG.MAIN, CONFIG.GEOCACHE, CONFIG.OU_CACHE, CONFIG.ACTIVE,
                    CONFIG.SUSPICIOUS, CONFIG.DIAG, CONFIG.ARCHIVE, 'Setup'];
  const missingSheets = required.filter(name => !ss.getSheetByName(name));
  const triggers = ScriptApp.getProjectTriggers().filter(t =>
    ['scheduledSync', 'weeklyReset', 'dailyDigest'].includes(t.getHandlerFunction())
  );
  return {
    installed: p.getProperty('INSTALL_COMPLETE') === 'true',
    installVersion: p.getProperty('INSTALL_VERSION') || '',
    installTimestamp: p.getProperty('INSTALL_TIMESTAMP') || '',
    lastRunISO: p.getProperty('lastRunISO') || '',
    triggerCount: triggers.length,
    missingSheets: missingSheets,
    config: getWizardConfig()
  };
}

function resetInstallState() {
  const ui = SpreadsheetApp.getUi();
  const choice = ui.alert(
    'Reset install state?',
    'This clears install metadata and lastRunISO, but does not delete your event data. Continue?',
    ui.ButtonSet.YES_NO
  );
  if (choice !== ui.Button.YES) return;
  const p = PropertiesService.getScriptProperties();
  p.deleteProperty('INSTALL_COMPLETE');
  p.deleteProperty('INSTALL_VERSION');
  p.deleteProperty('INSTALL_TIMESTAMP');
  p.deleteProperty('lastRunISO');
  SpreadsheetApp.getActive().toast('Install state reset.', 'Workspace Watchdog', 5);
}

function getWizardConfig() {
  _applyRuntimeConfig_();
  const p = PropertiesService.getScriptProperties();
  return {
    tz: CONFIG.TZ || 'America/Chicago',
    syncEveryMinutes: CONFIG.SYNC_EVERY_MINUTES,
    activeWindowMinutes: CONFIG.ACTIVE_WINDOW_MINUTES,
    firstRunLookbackMinutes: CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN,
    fastInstallLookbackMinutes: CONFIG.FAST_INSTALL_LOOKBACK_MINUTES,
    apiLagMinutes: CONFIG.API_LAG_MINUTES,
    overlapMinutes: CONFIG.OVERLAP_MINUTES,
    burstCount: CONFIG.BURST_COUNT,
    burstWindowMin: CONFIG.BURST_WINDOW_MIN,
    impossibleMinMiles: CONFIG.IMPOSSIBLE_MIN_MILES,
    impossibleMph: CONFIG.IMPOSSIBLE_MPH,
    geoTtlHours: CONFIG.GEO_TTL_HOURS,
    ouTtlHours: CONFIG.OU_TTL_HOURS,
    keepDays: CONFIG.KEEP_DAYS,
    trimAfterSync: CONFIG.TRIM_AFTER_SYNC,
    activeIncludeToken: CONFIG.ACTIVE_INCLUDE_TOKEN,
    cacheWarmupBatchIp: CONFIG.CACHE_WARMUP_BATCH_IP,
    cacheWarmupBatchUser: CONFIG.CACHE_WARMUP_BATCH_USER,
    cacheWarmupIntervalMinutes: CONFIG.CACHE_WARMUP_INTERVAL_MINUTES,
    ipinfoToken: p.getProperty('IPINFO_TOKEN') || '',
    monitorOUs: CONFIG.MONITOR_OUS || '',
    bulkOuLoad: CONFIG.BULK_OU_LOAD !== false,
    chatWebhookSet: !!(PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL')),
    chatAlertDedupeHours: CONFIG.CHAT_ALERT_DEDUPE_HOURS,
    chatAlertOnOutsideUS: CONFIG.CHAT_ALERT_ON_OUTSIDE_US,
    chatAlertOnImpossibleTravel: CONFIG.CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL,
    chatAlertOnBurst: CONFIG.CHAT_ALERT_ON_BURST,
    chatAlertOnPasswordLeak:   CONFIG.CHAT_ALERT_ON_PASSWORD_LEAK,
    chatAlertOnFailThreshold:  CONFIG.CHAT_ALERT_ON_FAIL_THRESHOLD,
    failThresholdCount:        CONFIG.FAIL_THRESHOLD_COUNT,
    chatAlertScheduledOnly: CONFIG.CHAT_ALERT_SCHEDULED_ONLY,
    digestEnabled:      CONFIG.DIGEST_ENABLED,
    digestEmailEnabled:   CONFIG.DIGEST_EMAIL_ENABLED,
    weeklyReportEnabled:  CONFIG.WEEKLY_REPORT_ENABLED,
    digestComparison:     CONFIG.DIGEST_COMPARISON,
    digestEmailTo:      CONFIG.DIGEST_EMAIL_TO,
    digestHour:       CONFIG.DIGEST_HOUR,
    campusIpFilter:   CONFIG.CAMPUS_IP_FILTER || '',
    installed: p.getProperty('INSTALL_COMPLETE') === 'true',
    installVersion: p.getProperty('INSTALL_VERSION') || '',
    installTimestamp: p.getProperty('INSTALL_TIMESTAMP') || ''
  };
}

function saveWizardConfig(form) {
  const p = PropertiesService.getScriptProperties();
  const cleanNum = (v, fallback) => { const n = Number(v); return isFinite(n) ? String(n) : String(fallback); };
  const cleanBool = (v) => String(!!v);

  p.setProperties({
    TZ: String(form.tz || 'America/Chicago'),
    SYNC_EVERY_MINUTES: cleanNum(form.syncEveryMinutes, 15),
    ACTIVE_WINDOW_MINUTES: cleanNum(form.activeWindowMinutes, 30),
    LOOKBACK_MINUTES_ON_FIRST_RUN: cleanNum(form.firstRunLookbackMinutes, 1440),
    FAST_INSTALL_LOOKBACK_MINUTES: cleanNum(form.fastInstallLookbackMinutes, 120),
    API_LAG_MINUTES: cleanNum(form.apiLagMinutes, 15),
    OVERLAP_MINUTES: cleanNum(form.overlapMinutes, 90),
    BURST_COUNT: cleanNum(form.burstCount, 5),
    BURST_WINDOW_MIN: cleanNum(form.burstWindowMin, 2),
    IMPOSSIBLE_MIN_MILES: cleanNum(form.impossibleMinMiles, 50),
    IMPOSSIBLE_MPH: cleanNum(form.impossibleMph, 500),
    GEO_TTL_HOURS: cleanNum(form.geoTtlHours, 168),
    OU_TTL_HOURS: cleanNum(form.ouTtlHours, 336),
    KEEP_DAYS: cleanNum(form.keepDays, 7),
    TRIM_AFTER_SYNC: cleanBool(form.trimAfterSync),
    ACTIVE_INCLUDE_TOKEN: cleanBool(form.activeIncludeToken),
    CACHE_WARMUP_BATCH_IP: cleanNum(form.cacheWarmupBatchIp, 10),
    CACHE_WARMUP_BATCH_USER: cleanNum(form.cacheWarmupBatchUser, 10),
    CACHE_WARMUP_INTERVAL_MINUTES: cleanNum(form.cacheWarmupIntervalMinutes, 5),
    IPINFO_TOKEN:   String(form.ipinfoToken || ''),
    MONITOR_OUS:    String(form.monitorOUs   || ''),
    BULK_OU_LOAD:   cleanBool(form.bulkOuLoad),
    CHAT_ALERT_DEDUPE_HOURS:         cleanNum(form.chatAlertDedupeHours, 12),
    CHAT_ALERT_ON_OUTSIDE_US:        cleanBool(form.chatAlertOnOutsideUS),
    CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: cleanBool(form.chatAlertOnImpossibleTravel),
    CHAT_ALERT_ON_BURST:             cleanBool(form.chatAlertOnBurst),
    CHAT_ALERT_ON_PASSWORD_LEAK:     cleanBool(form.chatAlertOnPasswordLeak),
    CHAT_ALERT_ON_FAIL_THRESHOLD:    cleanBool(form.chatAlertOnFailThreshold),
    FAIL_THRESHOLD_COUNT:            cleanNum(form.failThresholdCount, 10),
    CHAT_ALERT_SCHEDULED_ONLY:       cleanBool(form.chatAlertScheduledOnly),
    DIGEST_ENABLED:                  cleanBool(form.digestEnabled),
    DIGEST_EMAIL_ENABLED:            cleanBool(form.digestEmailEnabled),
    WEEKLY_REPORT_ENABLED:           cleanBool(form.weeklyReportEnabled),
    DIGEST_COMPARISON:               cleanBool(form.digestComparison),
    DIGEST_EMAIL_TO:                 String(form.digestEmailTo || '').trim(),
    DIGEST_HOUR:                     cleanNum(form.digestHour, 7),
    CAMPUS_IP_FILTER:                String(form.campusIpFilter || '').trim()
  });
  if (form.chatWebhookUrl && form.chatWebhookUrl.trim()) {
    PropertiesService.getScriptProperties().setProperty('CHAT_WEBHOOK_URL', form.chatWebhookUrl.trim());
  }
  _applyRuntimeConfig_();
  _ensureSetupSheet_();
  _saveSetupSummaryToSheet_();
  return { ok: true, message: 'Settings saved.' };
}

function installFromWizard(form) {
  saveWizardConfig(form);
  installWorkspaceWatchdog();
  return getSetupStatus();
}

function installFromWizardFast(form) {
  saveWizardConfig(form);
  fastInstallWorkspaceWatchdog(form.fastInstallLookbackMinutes);
  return getSetupStatus();
}

function testAdminAccess() {
  try {
    const now = new Date();
    const start = new Date(now.getTime() - 60 * 60000);
    AdminReports.Activities.list('all', 'login', {
      startTime: start.toISOString(), endTime: now.toISOString(), maxResults: 1
    });
    return { ok: true, message: 'Admin Reports access looks good.' };
  } catch (e) {
    return { ok: false, message: 'Admin Reports test failed: ' + (e && e.message ? e.message : e) };
  }
}

function testDirectoryAccess() {
  try {
    const me = Session.getActiveUser().getEmail();
    if (me) { try { AdminDirectory.Users.get(me); } catch (_) {} }
    AdminDirectory.Users.list({ customer: 'my_customer', maxResults: 1, orderBy: 'email' });
    return { ok: true, message: 'Admin Directory access looks good.' };
  } catch (e) {
    return { ok: false, message: 'Admin Directory test failed: ' + (e && e.message ? e.message : e) };
  }
}

function _ensureSetupSheet_() {
  const ss = SpreadsheetApp.getActive();
  let sh = ss.getSheetByName('Setup');
  if (!sh) sh = ss.insertSheet('Setup');
  const rows = [
    ['Workspace Watchdog Setup', ''],
    ['Version', WW_MONITOR_VERSION],
    ['Installed', PropertiesService.getScriptProperties().getProperty('INSTALL_COMPLETE') === 'true' ? 'Yes' : 'No'],
    ['Install Timestamp', PropertiesService.getScriptProperties().getProperty('INSTALL_TIMESTAMP') || ''],
    ['Last Run Cursor', PropertiesService.getScriptProperties().getProperty('lastRunISO') || ''],
    ['', ''],
    ['Setting', 'Value']
  ];
  sh.clear();
  sh.getRange(1, 1, rows.length, 2).setValues(rows);
  sh.getRange(1, 1).setFontWeight('bold').setFontSize(14);
  sh.getRange(7, 1, 1, 2).setFontWeight('bold');
  sh.setFrozenRows(7);
  sh.autoResizeColumns(1, 2);
}

function _saveSetupSummaryToSheet_() {
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName('Setup') || ss.insertSheet('Setup');
  const cfg = getWizardConfig();
  const values = [
    ['TZ', cfg.tz],
    ['SYNC_EVERY_MINUTES', cfg.syncEveryMinutes],
    ['ACTIVE_WINDOW_MINUTES', cfg.activeWindowMinutes],
    ['LOOKBACK_MINUTES_ON_FIRST_RUN', cfg.firstRunLookbackMinutes],
    ['FAST_INSTALL_LOOKBACK_MINUTES', cfg.fastInstallLookbackMinutes],
    ['API_LAG_MINUTES', cfg.apiLagMinutes],
    ['OVERLAP_MINUTES', cfg.overlapMinutes],
    ['BURST_COUNT', cfg.burstCount],
    ['BURST_WINDOW_MIN', cfg.burstWindowMin],
    ['IMPOSSIBLE_MIN_MILES', cfg.impossibleMinMiles],
    ['IMPOSSIBLE_MPH', cfg.impossibleMph],
    ['GEO_TTL_HOURS', cfg.geoTtlHours],
    ['OU_TTL_HOURS', cfg.ouTtlHours],
    ['KEEP_DAYS', cfg.keepDays],
    ['TRIM_AFTER_SYNC', cfg.trimAfterSync ? 'TRUE' : 'FALSE'],
    ['ACTIVE_INCLUDE_TOKEN', cfg.activeIncludeToken ? 'TRUE' : 'FALSE'],
    ['CACHE_WARMUP_BATCH_IP', cfg.cacheWarmupBatchIp],
    ['CACHE_WARMUP_BATCH_USER', cfg.cacheWarmupBatchUser],
    ['CACHE_WARMUP_INTERVAL_MINUTES', cfg.cacheWarmupIntervalMinutes],
    ['IPINFO_TOKEN_SET',  cfg.ipinfoToken  ? 'Yes' : 'No'],
    ['MONITOR_OUS',                  cfg.monitorOUs   || '(all)'],
    ['BULK_OU_LOAD',                 cfg.bulkOuLoad   ? 'TRUE' : 'FALSE'],
    ['CHAT_WEBHOOK_SET',             cfg.chatWebhookSet ? 'Yes' : 'No'],
    ['CHAT_ALERT_DEDUPE_HOURS',      cfg.chatAlertDedupeHours],
    ['CHAT_ALERT_ON_OUTSIDE_US',     cfg.chatAlertOnOutsideUS     ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL', cfg.chatAlertOnImpossibleTravel ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_ON_BURST',          cfg.chatAlertOnBurst         ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_SCHEDULED_ONLY',    cfg.chatAlertScheduledOnly   ? 'TRUE' : 'FALSE']
  ];
  const existingRows = Math.max(sh.getMaxRows() - 7, 1);
  sh.getRange(8, 1, existingRows, 2).clearContent();
  sh.getRange(8, 1, values.length, 2).setValues(values);
  sh.autoResizeColumns(1, 2);
}

function trimSetupSheetMenu() { trimSetupSheet(1); }

function trimSetupSheet(keepEntries) {
  keepEntries = keepEntries || 1;
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName('Setup');
  if (!sh || sh.getLastRow() <= 1) {
    SpreadsheetApp.getActive().toast('Setup sheet is already clean.', 'Workspace Watchdog', 3);
    return { ok: true, message: 'Already clean.' };
  }
  const vals = sh.getRange(1, 1, sh.getLastRow(), 1).getValues().flat();
  const blocks = [];
  let start = 0;
  for (let i = 0; i <= vals.length; i++) {
    if (i === vals.length || vals[i] === '') {
      if (i > start) blocks.push({ start, end: i });
      start = i + 1;
    }
  }
  if (blocks.length <= keepEntries) {
    SpreadsheetApp.getActive().toast('Only ' + blocks.length + ' entry — nothing to trim.', 'Workspace Watchdog', 3);
    return { ok: true, message: 'Nothing to trim.' };
  }
  const keepFrom = blocks[blocks.length - keepEntries].start + 1;
  if (keepFrom > 1) sh.deleteRows(1, keepFrom - 1);
  const removed = blocks.length - keepEntries;
  SpreadsheetApp.getActive().toast(
    'Removed ' + removed + ' old Setup snapshot(s). Kept ' + keepEntries + '.',
    'Workspace Watchdog', 5
  );
  return { ok: true, message: 'Removed ' + removed + ' snapshot(s).' };
}

function showLiveMap() {
  const html = HtmlService.createHtmlOutputFromFile('LiveMap')
    .setTitle('Workspace Watchdog - Live Map')
    .setWidth(2000)
    .setHeight(2000);
  SpreadsheetApp.getUi().showModalDialog(html, 'Live Map');
}

function getMapFullscreenUrl() {
  const p     = PropertiesService.getScriptProperties();
  const depId = p.getProperty('DEPLOYMENT_ID') || '';
  if (!depId) return null;
  return 'https://script.google.com/macros/s/' + depId + '/exec';
}

function showFullscreenMapUrl() {
  const url = getMapFullscreenUrl();
  const ui  = SpreadsheetApp.getUi();
  if (!url) {
    ui.alert(
      'Full-Screen Map Setup',
      'To enable full-screen mode:\n\n' +
      '1. Click Deploy → New Deployment\n' +
      '2. Type: Web App\n' +
      '3. Execute as: User accessing the web app\n' +
      '4. Who has access: Anyone in your organization\n' +
      '5. Copy the Deployment ID from the URL\n' +
      '6. Add it to Script Properties as DEPLOYMENT_ID\n' +
      '7. Add allowed emails to MAP_ALLOWED_USERS in Setup Wizard\n\n' +
      'No API_TOKEN needed. Google handles authentication.',
      ui.ButtonSet.OK
    );
    return;
  }
  const html = HtmlService.createHtmlOutput(
    '<div style="font-family:Arial,sans-serif;padding:16px;">' +
    '<p style="margin:0 0 12px;font-size:13px;color:#333;">Click the link below to open the full-screen Live Map. Bookmark it for direct access.</p>' +
    '<a href="' + url + '" target="_blank" ' +
    'style="display:block;background:#1a73e8;color:#fff;text-decoration:none;padding:10px 16px;' +
    'border-radius:4px;font-size:13px;font-weight:600;text-align:center;margin-bottom:12px;">' +
    '&#127760; Open Full-Screen Live Map</a>' +
    '<p style="margin:0;font-size:11px;color:#888;word-break:break-all;">' + url + '</p>' +
    '</div>'
  ).setWidth(480).setHeight(160);
  ui.showModalDialog(html, 'Full-Screen Live Map');
}
