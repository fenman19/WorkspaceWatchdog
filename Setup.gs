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
  ScriptApp.newTrigger('autoRetryFailedGeo').timeBased().everyHours(1).create();

  PropertiesService.getScriptProperties().deleteProperty('lastRunISO');

  PropertiesService.getScriptProperties().setProperties({
    INSTALL_COMPLETE: 'true',
    INSTALL_VERSION: WW_MONITOR_VERSION,
    INSTALL_TIMESTAMP: new Date().toISOString()
  });

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
    ScriptApp.newTrigger('autoRetryFailedGeo').timeBased().everyHours(1).create();

    p.setProperties({
      INSTALL_COMPLETE: 'true',
      INSTALL_VERSION: WW_MONITOR_VERSION,
      INSTALL_TIMESTAMP: new Date().toISOString()
    });

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
    .setWidth(1050)
    .setHeight(880);
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
  const expectedTriggerHandlers = [
    'scheduledSync',
    'weeklyReset',
    'cacheWarmup',
    'dailyDigest',
    'weeklyReport',
    'autoRetryFailedGeo'
  ];
  const projectTriggers = ScriptApp.getProjectTriggers();
  const installedTriggerHandlers = projectTriggers.map(t => t.getHandlerFunction());
  const watchdogTriggers = projectTriggers.filter(t =>
    expectedTriggerHandlers.includes(t.getHandlerFunction())
  );
  const missingTriggers = expectedTriggerHandlers.filter(name =>
    !installedTriggerHandlers.includes(name)
  );
  return {
    installed: p.getProperty('INSTALL_COMPLETE') === 'true',
    installVersion: p.getProperty('INSTALL_VERSION') || '',
    installTimestamp: p.getProperty('INSTALL_TIMESTAMP') || '',
    lastRunISO: p.getProperty('lastRunISO') || '',
    triggerCount: watchdogTriggers.length,
    expectedTriggerCount: expectedTriggerHandlers.length,
    missingTriggers: missingTriggers,
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
    ipinfoTokenSet: !!p.getProperty('IPINFO_TOKEN'),
    abuseIpDbKeySet: !!p.getProperty('ABUSEIPDB_KEY'),
    monitorOUs: CONFIG.MONITOR_OUS || '',
    bulkOuLoad: CONFIG.BULK_OU_LOAD !== false,
    chatWebhookSet: !!(PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL')),
    chatAlertDedupeHours: CONFIG.CHAT_ALERT_DEDUPE_HOURS,
    chatAlertOnOutsideUS: CONFIG.CHAT_ALERT_ON_OUTSIDE_US,
    chatAlertOnOutsideSafeStates: CONFIG.CHAT_ALERT_ON_OUTSIDE_SAFE_STATES,
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
    ignoreMobileImpossibleTravel: CONFIG.IGNORE_MOBILE_IMPOSSIBLE_TRAVEL,
    ignoreMobileStateMonitoring: CONFIG.IGNORE_MOBILE_STATE_MONITORING,
    mobileIspList: CONFIG.MOBILE_ISP_LIST || '',
    stateMonitoringEnabled: CONFIG.STATE_MONITORING_ENABLED,
    safeStates: CONFIG.SAFE_STATES || '',
    installed: p.getProperty('INSTALL_COMPLETE') === 'true',
    installVersion: p.getProperty('INSTALL_VERSION') || '',
    installTimestamp: p.getProperty('INSTALL_TIMESTAMP') || '',
    // License
    licenseTokenSet: !!p.getProperty('WW_LICENSE_KEY'),
    licenseTier:   p.getProperty('WW_LICENSE_TIER')   || '',
    licenseDomain: p.getProperty('WW_LICENSE_DOMAIN') || '',
    licenseExpires: p.getProperty('WW_LICENSE_EXPIRES') || '',
    licensePhase:   _getLicenseState_().phase
  };
}

function saveWizardConfig(form) {
  const p = PropertiesService.getScriptProperties();
  const cleanNum = (v, fallback) => { const n = Number(v); return isFinite(n) ? String(n) : String(fallback); };
  const cleanBool = (v) => String(!!v);
  const wasStateMonitoringEnabled = String(p.getProperty('STATE_MONITORING_ENABLED') || '').toLowerCase() === 'true';
  const stateMonitoringEnabled = !!form.stateMonitoringEnabled;
  const existingStateStart = String(p.getProperty('STATE_MONITORING_START_ISO') || '').trim();
  let stateMonitoringStartIso = '';
  if (stateMonitoringEnabled) {
    stateMonitoringStartIso = (!wasStateMonitoringEnabled || !existingStateStart)
      ? new Date().toISOString()
      : existingStateStart;
  }
  const safeStates = Array.from(new Set(_splitSafeStateList_(form.safeStates || ''))).sort();
  if (form.stateMonitoringEnabled && safeStates.length === 0) {
    throw new Error('State Monitoring is enabled, but no Safe States are selected. Select at least one Safe State or turn State Monitoring off.');
  }

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
    MONITOR_OUS:    String(form.monitorOUs   || ''),
    BULK_OU_LOAD:   cleanBool(form.bulkOuLoad),
    CHAT_ALERT_DEDUPE_HOURS:         cleanNum(form.chatAlertDedupeHours, 12),
    CHAT_ALERT_ON_OUTSIDE_US:        cleanBool(form.chatAlertOnOutsideUS),
    CHAT_ALERT_ON_OUTSIDE_SAFE_STATES: cleanBool(form.chatAlertOnOutsideSafeStates),
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
    CAMPUS_IP_FILTER:                String(form.campusIpFilter || '').trim(),
    IGNORE_MOBILE_IMPOSSIBLE_TRAVEL: cleanBool(form.ignoreMobileImpossibleTravel),
    IGNORE_MOBILE_STATE_MONITORING:  cleanBool(form.ignoreMobileStateMonitoring),
    MOBILE_ISP_LIST:                 String(form.mobileIspList || '').trim(),
    STATE_MONITORING_ENABLED:        cleanBool(form.stateMonitoringEnabled),
    SAFE_STATES:                     safeStates.join(','),
    STATE_MONITORING_START_ISO:      stateMonitoringStartIso
  });
  if (form.chatWebhookUrl && form.chatWebhookUrl.trim()) {
    PropertiesService.getScriptProperties().setProperty('CHAT_WEBHOOK_URL', form.chatWebhookUrl.trim());
  }
  if (form.ipinfoToken && form.ipinfoToken.trim()) {
    PropertiesService.getScriptProperties().setProperty('IPINFO_TOKEN', form.ipinfoToken.trim());
  }
  if (form.abuseIpDbKey && form.abuseIpDbKey.trim()) {
    PropertiesService.getScriptProperties().setProperty('ABUSEIPDB_KEY', form.abuseIpDbKey.trim());
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
    return {
      ok: true,
      code: 'ok',
      title: 'Admin Reports API ready',
      message: 'Workspace Watchdog can read login audit events.'
    };
  } catch (e) {
    return _buildApiTestFailure_('reports', e);
  }
}

function testDirectoryAccess() {
  try {
    const me = Session.getActiveUser().getEmail();
    if (me) { try { AdminDirectory.Users.get(me); } catch (_) {} }
    AdminDirectory.Users.list({ customer: 'my_customer', maxResults: 1, orderBy: 'email' });
    return {
      ok: true,
      code: 'ok',
      title: 'Admin Directory API ready',
      message: 'Workspace Watchdog can read the user directory and organizational units.'
    };
  } catch (e) {
    return _buildApiTestFailure_('directory', e);
  }
}

function _buildApiTestFailure_(apiName, error) {
  const raw = String(error && error.message ? error.message : error || 'Unknown error');
  const lower = raw.toLowerCase();
  let code = 'unknown';
  let title = 'API test failed';
  let steps = [];

  if (lower.includes('not defined') || lower.includes('is not defined')) {
    code = 'advanced_service_missing';
    title = 'Advanced service is not available';
    steps = [
      'Open the Apps Script editor.',
      'In the left panel, open Services and confirm Admin SDK API is listed.',
      'Return to this wizard and click Retest.'
    ];
  } else if (lower.includes('access not configured') || lower.includes('has not been used') || lower.includes('disabled')) {
    code = 'cloud_api_disabled';
    title = 'Admin SDK API is disabled';
    steps = [
      'Open the Google Cloud API page from the link below.',
      'Enable Admin SDK API for this script project.',
      'Wait about one minute, then return and click Retest.'
    ];
  } else if (lower.includes('authorization') || lower.includes('permission') || lower.includes('insufficient') || lower.includes('forbidden') || lower.includes('not authorized')) {
    code = 'permission_denied';
    title = 'Administrator permission is required';
    steps = [
      'Confirm you are signed in with a Google Workspace administrator account.',
      'Run the test again and approve any Google authorization prompt.',
      'If your organization restricts Apps Script, ask a super administrator to allow this customer-owned script.'
    ];
  } else {
    steps = [
      'Confirm you are signed in with a Google Workspace administrator account.',
      'Open the Apps Script editor and verify Admin SDK API appears under Services.',
      'Retest. If it still fails, copy the diagnostic text for support.'
    ];
  }

  return {
    ok: false,
    api: apiName,
    code: code,
    title: title,
    message: raw,
    steps: steps,
    links: getSetupGuideLinks()
  };
}

function getSetupGuideLinks() {
  const scriptId = ScriptApp.getScriptId();
  const editorBase = 'https://script.google.com/home/projects/' + encodeURIComponent(scriptId);
  return {
    scriptEditor: editorBase + '/edit',
    projectSettings: editorBase + '/settings',
    deployments: editorBase + '/deployments',
    cloudProjects: 'https://console.cloud.google.com/cloud-resource-manager',
    oauthOverview: 'https://console.cloud.google.com/auth/overview',
    oauthAudience: 'https://console.cloud.google.com/auth/audience',
    oauthDataAccess: 'https://console.cloud.google.com/auth/scopes',
    cloudProjectHelp: 'https://developers.google.com/apps-script/guides/cloud-platform-projects#determine_the_id_&_number_of_a_standard_cloud_project',
    adminSdkApi: 'https://console.cloud.google.com/apis/library/admin.googleapis.com',
    appsScriptApi: 'https://console.cloud.google.com/apis/library/script.googleapis.com',
    appsScriptDashboard: 'https://script.google.com/home/usersettings',
    appsScriptApiHelp: 'https://developers.google.com/apps-script/api/how-tos/enable',
    scriptPropertiesHelp: 'https://developers.google.com/apps-script/guides/properties',
    ipInfo: 'https://ipinfo.io/signup',
    abuseIpDb: 'https://www.abuseipdb.com/register',
    support: 'https://workspacewatchdog.com'
  };
}

function getInstallationHealth() {
  const status = getSetupStatus();
  const p = PropertiesService.getScriptProperties();
  const reports = testAdminAccess();
  const directory = testDirectoryAccess();
  const deploymentId = p.getProperty('DEPLOYMENT_ID') || '';

  const checks = [
    { id: 'license', label: 'License activated', required: true, ok: !!p.getProperty('WW_LICENSE_KEY'), detail: p.getProperty('WW_LICENSE_TIER') || 'No license token stored' },
    { id: 'reports', label: 'Admin Reports API', required: true, ok: !!reports.ok, detail: reports.ok ? reports.message : reports.title },
    { id: 'directory', label: 'Admin Directory API', required: true, ok: !!directory.ok, detail: directory.ok ? directory.message : directory.title },
    { id: 'sheets', label: 'Required sheets', required: true, ok: status.missingSheets.length === 0, detail: status.missingSheets.length ? 'Missing: ' + status.missingSheets.join(', ') : 'All required sheets are present' },
    { id: 'triggers', label: 'Scheduled triggers', required: true, ok: status.missingTriggers.length === 0, detail: status.missingTriggers.length ? 'Missing: ' + status.missingTriggers.join(', ') : status.triggerCount + ' of ' + status.expectedTriggerCount + ' installed' },
    { id: 'firstSync', label: 'Initial sync cursor', required: true, ok: !!status.lastRunISO, detail: status.lastRunISO || 'No completed sync detected yet' },
    { id: 'mapDeployment', label: 'Full-screen map deployment', required: false, ok: !!deploymentId, detail: deploymentId ? 'Deployment ID configured' : 'Optional — not configured' }
  ];

  const requiredChecks = checks.filter(c => c.required);
  return {
    ok: requiredChecks.every(c => c.ok),
    installed: status.installed,
    version: status.installVersion || WW_MONITOR_VERSION,
    checks: checks,
    links: getSetupGuideLinks(),
    reportsResult: reports,
    directoryResult: directory
  };
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
    ['IGNORE_MOBILE_IMPOSSIBLE_TRAVEL', cfg.ignoreMobileImpossibleTravel ? 'TRUE' : 'FALSE'],
    ['IGNORE_MOBILE_STATE_MONITORING', cfg.ignoreMobileStateMonitoring ? 'TRUE' : 'FALSE'],
    ['MOBILE_ISP_LIST', cfg.mobileIspList || '(none selected)'],
    ['STATE_MONITORING_ENABLED', cfg.stateMonitoringEnabled ? 'TRUE' : 'FALSE'],
    ['SAFE_STATES', cfg.safeStates || '(none selected)'],
    ['GEO_TTL_HOURS', cfg.geoTtlHours],
    ['OU_TTL_HOURS', cfg.ouTtlHours],
    ['KEEP_DAYS', cfg.keepDays],
    ['TRIM_AFTER_SYNC', cfg.trimAfterSync ? 'TRUE' : 'FALSE'],
    ['ACTIVE_INCLUDE_TOKEN', cfg.activeIncludeToken ? 'TRUE' : 'FALSE'],
    ['CACHE_WARMUP_BATCH_IP', cfg.cacheWarmupBatchIp],
    ['CACHE_WARMUP_BATCH_USER', cfg.cacheWarmupBatchUser],
    ['CACHE_WARMUP_INTERVAL_MINUTES', cfg.cacheWarmupIntervalMinutes],
    ['IPINFO_TOKEN_SET',  cfg.ipinfoTokenSet  ? 'Yes' : 'No'],
    ['ABUSEIPDB_KEY_SET', cfg.abuseIpDbKeySet ? 'Yes' : 'No'],
    ['MONITOR_OUS',                  cfg.monitorOUs   || '(all)'],
    ['BULK_OU_LOAD',                 cfg.bulkOuLoad   ? 'TRUE' : 'FALSE'],
    ['CHAT_WEBHOOK_SET',             cfg.chatWebhookSet ? 'Yes' : 'No'],
    ['CHAT_ALERT_DEDUPE_HOURS',      cfg.chatAlertDedupeHours],
    ['CHAT_ALERT_ON_OUTSIDE_US',     cfg.chatAlertOnOutsideUS     ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_ON_OUTSIDE_SAFE_STATES', cfg.chatAlertOnOutsideSafeStates ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL', cfg.chatAlertOnImpossibleTravel ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_ON_BURST',          cfg.chatAlertOnBurst         ? 'TRUE' : 'FALSE'],
    ['CHAT_ALERT_SCHEDULED_ONLY',    cfg.chatAlertScheduledOnly   ? 'TRUE' : 'FALSE'],
    ['LICENSE_TIER',                 cfg.licenseTier  || '(none)'],
    ['LICENSE_DOMAIN',               cfg.licenseDomain || '(none)']
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
  const state = _getLicenseState_();
  if (state.phase === 'mapLocked' || state.phase === 'shutdown') {
    SpreadsheetApp.getUi().alert(
      'Live Map Unavailable',
      'Your license expired on ' + state.expiresOn + '. The Live Map is disabled until a renewed ' +
      'license is activated.\n\nVisit workspacewatchdog.com to renew, or open the Setup Wizard to enter a new token.',
      SpreadsheetApp.getUi().ButtonSet.OK
    );
    return;
  }
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
