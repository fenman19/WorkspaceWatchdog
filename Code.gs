/* global AdminReports, AdminDirectory */
/**
 * Google Workspace Login Monitor v3.1.0
 * Added updater to Toolbar in LiveMap
 * Redesigned toolbar for LiveMap
 * Added Globes to LiveMap
 * New in v2.8: Daily email digest + Weekly Summary
 * New in v2.7: Suspicious event whitelist — suppress known-safe users/IPs
 * New in v2.6.1: Full-screen standalone map via Web App deployment
 * New in v2.6: Live Map — sheet-native clustered interactive map (LiveMap.html)
 * New in v2.5: Google Chat alerts for Outside US, Impossible Travel, Login Burst
 * New in v2.4: strip ASN prefix (AS12345) from ISP field for cleaner display
 * New in v2.3: lat+lon combined into single LatLng column on all output sheets
 * New in v2.2: guard lastRunISO so it is never written on a zero-row first run
 * New in v2.1: batch sheet writes for OU and geo upserts (O(n) → O(1) I/O)
 * New in v2:
 *   - OU filtering: monitor specific OUs only (CONFIG.MONITOR_OUS)
 *   - Bulk OU load: one Directory API call for all users (CONFIG.BULK_OU_LOAD)
 *   - Parallel geo: fetchAll batching for IP enrichment
 *   - Key index: O(1) deduplication via hidden KeyIndex sheet (no full rewrites)
 * Timezone: America/Chicago (configurable)
 * - Main (deduped): Timestamp, Actor Email, Event Name, IP, City, Region, Country, Raw JSON, Event Key,
 *   LatLng, GeoSource, Org Unit Path,
 *   ParsedTSNoTZ, HourBucket, OutsideUS, HasGeo, TopOU
 * - GeoCache: IP → geo (cache)
 * - OUCache: Email → OrgUnitPath (cache)
 * - Active Now: windowed active + latest login geo + OU + precomputed fields
 * - Suspicious: Outside US, Bursts, Impossible Travel (+ precomputed fields)
 * - Diagnostics: run metrics
 * - Archive: only rows older than KEEP_DAYS get appended here (rolling trim)
 */

let CONFIG = {
  TZ: 'America/Chicago',
  // Sheet names
  MAIN: 'Main',
  GEOCACHE: 'GeoCache',
  OU_CACHE: 'OUCache',
  ACTIVE: 'Active Now',
  SUSPICIOUS: 'Suspicious',
  DIAG: 'Diagnostics',
  ARCHIVE: 'Archive',
  // Cadence & windows
  SYNC_EVERY_MINUTES: 15,
  ACTIVE_WINDOW_MINUTES: 30,
  LOOKBACK_MINUTES_ON_FIRST_RUN: 60 * 24, // 24h
  FAST_INSTALL_LOOKBACK_MINUTES: 120, // default fast-install seed window
  API_LAG_MINUTES: 15,
  OVERLAP_MINUTES: 90,
  // Suspicious thresholds
  BURST_COUNT: 5,
  BURST_WINDOW_MIN: 2,
  IMPOSSIBLE_MIN_MILES: 50,
  IMPOSSIBLE_MPH: 500,
  // Cache TTL
  GEO_TTL_HOURS: 24 * 7,
  OU_TTL_HOURS: 24 * 14,
  // Active sources
  ACTIVE_INCLUDE_TOKEN: true,
  // Rolling retention
  KEEP_DAYS: 7,           // keep only the last N days in Main
  TRIM_AFTER_SYNC: true,  // trim right after each sync

  // Background cache warmup
  CACHE_WARMUP_BATCH_IP: 10,
  CACHE_WARMUP_BATCH_USER: 10,
  CACHE_WARMUP_INTERVAL_MINUTES: 5,

  // OU filtering — comma-separated list of OU paths to monitor.
  // Subtrees are included automatically: '/Staff' also includes '/Staff/Teachers'.
  // Leave empty ('') to monitor ALL users (default).
  MONITOR_OUS: '',

  // Bulk OU load — pre-fetches all users from Directory API in one paginated
  // call instead of one-at-a-time lookups. Critical for domains >500 accounts.
  BULK_OU_LOAD: true,

  // Google Chat alerts — set CHAT_WEBHOOK_URL in Script Properties.
  // CHAT_ALERT_DEDUPE_HOURS: how long to suppress repeat alerts for the same event.
  // CHAT_ALERT_ON_OUTSIDE_US: alert on logins from outside the US.
  // CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: alert on impossible travel detections.
  // CHAT_ALERT_ON_BURST: alert on login burst detections.
  // CHAT_ALERT_SCHEDULED_ONLY: only send alerts during scheduledSync (not installs/backfills).
  CHAT_ALERT_DEDUPE_HOURS: 12,
  CHAT_ALERT_ON_OUTSIDE_US: true,
  CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: true,
  CHAT_ALERT_ON_BURST: true,
  CHAT_ALERT_ON_PASSWORD_LEAK: true,   // alert when Google detects a password leak
  CHAT_ALERT_ON_FAIL_THRESHOLD: true,  // alert when a user exceeds daily failed login threshold
  FAIL_THRESHOLD_COUNT: 10,            // number of failures in 24h to trigger alert
  CHAT_ALERT_SCHEDULED_ONLY: true,

  // Daily Chat digest — sends a summary to your Google Chat space each morning.
  // Uses CHAT_WEBHOOK_URL. DIGEST_HOUR: CT hour to send (0-23, default 7 = 7am).
  DIGEST_ENABLED: false,
  DIGEST_HOUR: 7,
  DIGEST_EMAIL_ENABLED: true,    // send HTML email digest in addition to Chat
  DIGEST_EMAIL_TO: '',           // extra recipient(s), comma-separated; script owner always gets it
  WEEKLY_REPORT_ENABLED: true,   // send weekly summary email every Monday
  DIGEST_COMPARISON: true,       // show vs-yesterday deltas in daily digest email

  // IP Reputation — AbuseIPDB lookup for suspicious IPs.
  // Set ABUSEIPDB_KEY in Script Properties (free API key from abuseipdb.com).
  // IP_REP_MIN_SCORE: minimum abuse confidence score (0-100) to flag an IP.
  // IP_REP_CACHE_DAYS: how long to cache reputation results per IP.
  IP_REP_ENABLED: false,
  IP_REP_MIN_SCORE: 25,
  IP_REP_CACHE_DAYS: 3
};

// ===== Cache Indexes (large-domain performance) ==============================
var __GEO_INDEX = null;      // IP  -> geo object
var __OU_INDEX  = null;      // email (lower) -> {ou, lastSeenISO}
var __GEO_ROW_INDEX = null;  // IP  -> 1-based sheet row number (skips header)
var __OU_ROW_INDEX  = null;  // email (lower) -> 1-based sheet row number

// ===== Headers (PRECOMPUTED FIELDS APPENDED) =================================
const MAIN_HEADERS = [
  'Timestamp','Actor Email','Event Name','IP','City','Region','Country','ISP','Raw JSON','Event Key',
  'LatLng','GeoSource','Org Unit Path',
  // precomputed (no LS formulas needed)
  'ParsedTSNoTZ','HourBucket','OutsideUS','HasGeo','TopOU'
];
const GEO_HEADERS = ['IP','City','Region','Country','ISP','Latitude','Longitude','Source','LastSeenISO'];
const OU_HEADERS  = ['Email','OrgUnitPath','LastSeenISO'];

const ACTIVE_HEADERS = [
  'Email','OU','FirstSeen (CT)','LastSeen (CT)','Sources','WindowMin','Count',
  'Last IP','City','Region','Country','ISP','LatLng','GeoSource',
  // precomputed
  'LastSeenNoTZ','HourBucket','AN_OutsideUS','AN_HasGeo'
];

const SUSP_HEADERS  = [
  'Timestamp (CT)','Actor Email','Reason','Details',
  'From City','From Region','From Country','From LatLng',
  'To City','To Region','To Country','To LatLng',
  'Distance (mi)','Speed (mph)','EventKey A','EventKey B',
  // precomputed
  'SuspNoTZ','HourBucket','Severity','Alerted'
];
const SUSP_ALERTED_COL = 19; // 1-based column index of Alerted

const DIAG_HEADERS = [
  'Trigger','Start (CT)','End (CT)','Events Parsed','Rows Appended','Notes',
  // ---- overlap/lag monitor (appended) ----
  'LagMin','OverlapMin','NewRows','DupesInWindow',
  'MainRowsBefore','MainRowsAfter','DedupeRemoved',
  'TrimArchived','TrimKept',
  'WindowStartISO','WindowEndISO'
];


// ===== Install, Wizard & Triggers ===========================================

const WW_MONITOR_VERSION = '2.8.0';

function _applyRuntimeConfig_() {
  const p = PropertiesService.getScriptProperties();

  const num = (key, fallback) => {
    const v = p.getProperty(key);
    if (v === null || v === '') return fallback;
    const n = Number(v);
    return isFinite(n) ? n : fallback;
  };

  const bool = (key, fallback) => {
    const v = p.getProperty(key);
    if (v === null || v === '') return fallback;
    return String(v).toLowerCase() === 'true';
  };

  const str = (key, fallback) => {
    const v = p.getProperty(key);
    return (v === null || v === '') ? fallback : v;
  };

  CONFIG.TZ = str('TZ', CONFIG.TZ);
  CONFIG.SYNC_EVERY_MINUTES = num('SYNC_EVERY_MINUTES', CONFIG.SYNC_EVERY_MINUTES);
  CONFIG.ACTIVE_WINDOW_MINUTES = num('ACTIVE_WINDOW_MINUTES', CONFIG.ACTIVE_WINDOW_MINUTES);
  CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN = num('LOOKBACK_MINUTES_ON_FIRST_RUN', CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN);
  CONFIG.FAST_INSTALL_LOOKBACK_MINUTES = num('FAST_INSTALL_LOOKBACK_MINUTES', CONFIG.FAST_INSTALL_LOOKBACK_MINUTES);
  CONFIG.API_LAG_MINUTES = num('API_LAG_MINUTES', CONFIG.API_LAG_MINUTES);
  CONFIG.OVERLAP_MINUTES = num('OVERLAP_MINUTES', CONFIG.OVERLAP_MINUTES);
  CONFIG.BURST_COUNT = num('BURST_COUNT', CONFIG.BURST_COUNT);
  CONFIG.BURST_WINDOW_MIN = num('BURST_WINDOW_MIN', CONFIG.BURST_WINDOW_MIN);
  CONFIG.IMPOSSIBLE_MIN_MILES = num('IMPOSSIBLE_MIN_MILES', CONFIG.IMPOSSIBLE_MIN_MILES);
  CONFIG.IMPOSSIBLE_MPH = num('IMPOSSIBLE_MPH', CONFIG.IMPOSSIBLE_MPH);
  CONFIG.GEO_TTL_HOURS = num('GEO_TTL_HOURS', CONFIG.GEO_TTL_HOURS);
  CONFIG.OU_TTL_HOURS = num('OU_TTL_HOURS', CONFIG.OU_TTL_HOURS);
  CONFIG.ACTIVE_INCLUDE_TOKEN = bool('ACTIVE_INCLUDE_TOKEN', CONFIG.ACTIVE_INCLUDE_TOKEN);
  CONFIG.KEEP_DAYS = num('KEEP_DAYS', CONFIG.KEEP_DAYS);
  CONFIG.TRIM_AFTER_SYNC  = bool('TRIM_AFTER_SYNC',  CONFIG.TRIM_AFTER_SYNC);
  CONFIG.MONITOR_OUS               = str ('MONITOR_OUS',               CONFIG.MONITOR_OUS);
  CONFIG.BULK_OU_LOAD              = bool('BULK_OU_LOAD',              CONFIG.BULK_OU_LOAD);
  CONFIG.CHAT_ALERT_DEDUPE_HOURS   = num ('CHAT_ALERT_DEDUPE_HOURS',   CONFIG.CHAT_ALERT_DEDUPE_HOURS);
  CONFIG.CHAT_ALERT_ON_OUTSIDE_US  = bool('CHAT_ALERT_ON_OUTSIDE_US',  CONFIG.CHAT_ALERT_ON_OUTSIDE_US);
  CONFIG.CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL = bool('CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL', CONFIG.CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL);
  CONFIG.CHAT_ALERT_ON_BURST       = bool('CHAT_ALERT_ON_BURST',       CONFIG.CHAT_ALERT_ON_BURST);
  CONFIG.CHAT_ALERT_ON_PASSWORD_LEAK     = bool('CHAT_ALERT_ON_PASSWORD_LEAK',     CONFIG.CHAT_ALERT_ON_PASSWORD_LEAK);
  CONFIG.CHAT_ALERT_ON_FAIL_THRESHOLD   = bool('CHAT_ALERT_ON_FAIL_THRESHOLD',   CONFIG.CHAT_ALERT_ON_FAIL_THRESHOLD);
  CONFIG.FAIL_THRESHOLD_COUNT           = num ('FAIL_THRESHOLD_COUNT',           CONFIG.FAIL_THRESHOLD_COUNT);
  CONFIG.CHAT_ALERT_SCHEDULED_ONLY       = bool('CHAT_ALERT_SCHEDULED_ONLY',       CONFIG.CHAT_ALERT_SCHEDULED_ONLY);
  CONFIG.DIGEST_ENABLED                  = bool('DIGEST_ENABLED',                  CONFIG.DIGEST_ENABLED);
  CONFIG.DIGEST_HOUR                     = num ('DIGEST_HOUR',                     CONFIG.DIGEST_HOUR);
  CONFIG.DIGEST_EMAIL_ENABLED            = bool('DIGEST_EMAIL_ENABLED',            CONFIG.DIGEST_EMAIL_ENABLED);
  CONFIG.WEEKLY_REPORT_ENABLED           = bool('WEEKLY_REPORT_ENABLED',           CONFIG.WEEKLY_REPORT_ENABLED);
  CONFIG.DIGEST_COMPARISON               = bool('DIGEST_COMPARISON',               CONFIG.DIGEST_COMPARISON);
  CONFIG.DIGEST_EMAIL_TO                 = PropertiesService.getScriptProperties().getProperty('DIGEST_EMAIL_TO') || '';
  CONFIG.IP_REP_ENABLED                  = bool('IP_REP_ENABLED',                  CONFIG.IP_REP_ENABLED);
  CONFIG.IP_REP_MIN_SCORE                = num ('IP_REP_MIN_SCORE',                CONFIG.IP_REP_MIN_SCORE);
  CONFIG.IP_REP_CACHE_DAYS               = num ('IP_REP_CACHE_DAYS',               CONFIG.IP_REP_CACHE_DAYS);
}

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
    )
    .addSubMenu(SpreadsheetApp.getUi().createMenu('Diagnostics & Testing')
      .addItem('Test Chat Alert',        'testChatAlert')
      .addItem('Send Digest Now',        'sendDailyDigestNow')
      .addItem('Send Weekly Report Now', 'sendWeeklyReportNow')
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

  // Clear lastRunISO so the first sync always uses the full lookback window.
  // This prevents a stale cursor from a previous install attempt causing zero rows.
  PropertiesService.getScriptProperties().deleteProperty('lastRunISO');

  PropertiesService.getScriptProperties().setProperties({
    INSTALL_COMPLETE: 'true',
    INSTALL_VERSION: WW_MONITOR_VERSION,
    INSTALL_TIMESTAMP: new Date().toISOString()
  }, true);

  // Pre-warm OUCache with all users so first sync can filter immediately
  if (CONFIG.BULK_OU_LOAD) {
    SpreadsheetApp.getActive().toast('Pre-loading OU cache...', 'Install', 5);
    _bulkLoadAllOUs_(SpreadsheetApp.getActive().getSheetByName(CONFIG.OU_CACHE));
  }
  // Seed the KeyIndex from any existing Main data (safe no-op on fresh install)
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

    // Clear lastRunISO so the seed sync always uses the full fast-install lookback.
    p.deleteProperty('lastRunISO');

    // Pre-warm OUCache before the seed sync so OU filter works immediately
    if (CONFIG.BULK_OU_LOAD) {
      SpreadsheetApp.getActive().toast('Pre-loading OU cache...', 'Workspace Watchdog', 5);
      _bulkLoadAllOUs_(SpreadsheetApp.getActive().getSheetByName(CONFIG.OU_CACHE));
    }
    rebuildKeyIndex();

    SpreadsheetApp.getActive().toast(
      'Fast Install complete. Running ' + fastLookbackMinutes + ' minute seed sync...',
      'Workspace Watchdog',
      5
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

function scheduledSync() {
  _applyRuntimeConfig_();
  _syncCore('scheduledSync');
}


/**
 * Cleans up old ww_alert_ keys from Script Properties.
 * Deletes any alert dedup entry older than 30 days.
 * Called from weeklyReset so it runs nightly automatically.
 */
function _cleanupAlertKeys_() {
  try {
    const p      = PropertiesService.getScriptProperties();
    const all    = p.getKeys();
    const cutoff = Date.now() - 30 * 24 * 3600000; // 30 days ago
    let   deleted = 0;
    all.forEach(k => {
      if (!k.startsWith('ww_alert_') && !k.startsWith('ww_alerted_') && !k.startsWith('ww_chat_digest_') && !k.startsWith('ww_weekly_report_')) return;
      try {
        const val = p.getProperty(k);
        const ts  = Number(val);
        // For keys storing ISO dates (digest dedup), parse as date
        const tsMs = isFinite(ts) ? ts : new Date(val).getTime();
        if (isFinite(tsMs) && tsMs < cutoff) {
          p.deleteProperty(k);
          deleted++;
        }
      } catch(e) {}
    });
    if (deleted > 0) {
      _logDiagnostics('alertKeyCleanup', new Date(), new Date(), deleted, 0,
        'Deleted ' + deleted + ' expired alert dedup key(s) from Script Properties.');
    }
  } catch(e) {}
}

/**
 * Trims the Setup sheet to keep only the most recent N config snapshots.
 * Each snapshot is a block separated by a blank row.
 * Called manually from the wizard or menu.
 */

function trimSetupSheetMenu() {
  trimSetupSheet(1);
}


/**
 * One-time purge of ALL ww_alert_ and ww_alerted_ keys from Script Properties.
 * Use when the 50-property limit is hit. Safe to run — config keys are untouched.
 */
function purgeAlertKeys() {
  const p    = PropertiesService.getScriptProperties();
  const all  = p.getKeys();
  let deleted = 0;
  all.forEach(k => {
    if (k.startsWith('ww_alert_') || k.startsWith('ww_alerted_') ||
        k.startsWith('ww_chat_digest_') || k.startsWith('ww_weekly_report_')) {
      p.deleteProperty(k);
      deleted++;
    }
  });
  SpreadsheetApp.getActive().toast(
    'Purged ' + deleted + ' alert dedup key(s) from Script Properties.',
    'Workspace Watchdog', 5);
}

function cleanupAlertKeysNow() {
  _cleanupAlertKeys_();
  SpreadsheetApp.getActive().toast('Alert key cleanup complete. Check Diagnostics for details.', 'Workspace Watchdog', 5);
}

function trimSetupSheet(keepEntries) {
  keepEntries = keepEntries || 1;
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName('Setup');
  if (!sh || sh.getLastRow() <= 1) {
    SpreadsheetApp.getActive().toast('Setup sheet is already clean.', 'Workspace Watchdog', 3);
    return { ok: true, message: 'Already clean.' };
  }

  const vals = sh.getRange(1, 1, sh.getLastRow(), 1).getValues().flat();

  // Find block boundaries — blocks are separated by blank rows
  const blocks = [];
  let start = 0;
  for (let i = 0; i <= vals.length; i++) {
    if (i === vals.length || vals[i] === '') {
      if (i > start) blocks.push({ start, end: i });
      start = i + 1;
    }
  }

  if (blocks.length <= keepEntries) {
    SpreadsheetApp.getActive().toast('Only ' + blocks.length + ' entry — nothing to trim.',
      'Workspace Watchdog', 3);
    return { ok: true, message: 'Nothing to trim.' };
  }

  // Keep only the last N blocks — clear everything before them
  const keepFrom = blocks[blocks.length - keepEntries].start + 1; // 1-based
  if (keepFrom > 1) {
    sh.deleteRows(1, keepFrom - 1);
  }

  const removed = blocks.length - keepEntries;
  SpreadsheetApp.getActive().toast(
    'Removed ' + removed + ' old Setup snapshot(s). Kept ' + keepEntries + '.',
    'Workspace Watchdog', 5);
  return { ok: true, message: 'Removed ' + removed + ' snapshot(s).' };
}

function weeklyReset() {
  _applyRuntimeConfig_();
  trimMainRolling();
  _cleanupAlertKeys_();
}

function showLiveMap() {
  // Apps Script caps modal dialogs at ~95% of the viewport.
  // Using large values lets the browser fill as much as it allows.
  const html = HtmlService.createHtmlOutputFromFile('LiveMap')
    .setTitle('Workspace Watchdog - Live Map')
    .setWidth(2000)
    .setHeight(2000);
  SpreadsheetApp.getUi().showModalDialog(html, 'Live Map');
}

/**
 * Returns the full-screen URL for the live map web app.
 * Requires DEPLOYMENT_ID set in Script Properties.
 * Access is controlled by MAP_ALLOWED_USERS (comma-separated emails).
 * Called from LiveMap.html to build the "Open Full Screen" link.
 */
function getMapFullscreenUrl() {
  const p     = PropertiesService.getScriptProperties();
  const depId = p.getProperty('DEPLOYMENT_ID') || '';
  if (!depId) return null;
  return 'https://script.google.com/macros/s/' + depId + '/exec';
}

/**
 * Menu helper — shows the full-screen URL so the user can bookmark it,
 * or prompts them to set up the Web App deployment if not configured.
 */
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
  // Show a clickable HTML dialog instead of plain text alert
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

  const required = [
    CONFIG.MAIN,
    CONFIG.GEOCACHE,
    CONFIG.OU_CACHE,
    CONFIG.ACTIVE,
    CONFIG.SUSPICIOUS,
    CONFIG.DIAG,
    CONFIG.ARCHIVE,
    'Setup'
  ];

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

    installed: p.getProperty('INSTALL_COMPLETE') === 'true',
    installVersion: p.getProperty('INSTALL_VERSION') || '',
    installTimestamp: p.getProperty('INSTALL_TIMESTAMP') || ''
  };
}

function saveWizardConfig(form) {
  const p = PropertiesService.getScriptProperties();

  const cleanNum = (v, fallback) => {
    const n = Number(v);
    return isFinite(n) ? String(n) : String(fallback);
  };

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
    DIGEST_HOUR:                     cleanNum(form.digestHour, 7)
  }); // No deleteOthers — preserve existing Script Properties
  // Store sensitive keys separately — never logged to Setup sheet
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
      startTime: start.toISOString(),
      endTime: now.toISOString(),
      maxResults: 1
    });

    return {
      ok: true,
      message: 'Admin Reports access looks good.'
    };
  } catch (e) {
    return {
      ok: false,
      message: 'Admin Reports test failed: ' + (e && e.message ? e.message : e)
    };
  }
}

function testDirectoryAccess() {
  try {
    const me = Session.getActiveUser().getEmail();
    if (me) {
      try {
        AdminDirectory.Users.get(me);
      } catch (_) {}
    }

    AdminDirectory.Users.list({
      customer: 'my_customer',
      maxResults: 1,
      orderBy: 'email'
    });

    return {
      ok: true,
      message: 'Admin Directory access looks good.'
    };
  } catch (e) {
    return {
      ok: false,
      message: 'Admin Directory test failed: ' + (e && e.message ? e.message : e)
    };
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

// ===== Core Sync =============================================================

function _syncCore(triggerName) {
  _resetAllCaches_();
  const __ouMap = __getOUMap();
  const t0 = new Date();
  let eventsParsed = 0, rowsAppended = 0, note = '';

  try {
    const ss = SpreadsheetApp.getActive();
    const shMain = ss.getSheetByName(CONFIG.MAIN);
    const shGeo = ss.getSheetByName(CONFIG.GEOCACHE);
    const shOU  = ss.getSheetByName(CONFIG.OU_CACHE);

    // window w/ lag & overlap
    const props = PropertiesService.getScriptProperties();
    const now = new Date();
    const endU = new Date(now.getTime() - CONFIG.API_LAG_MINUTES*60000);
    const lastRunISO = props.getProperty('lastRunISO');
    const startU = lastRunISO
      ? new Date(new Date(lastRunISO).getTime() - CONFIG.OVERLAP_MINUTES*60000)
      : new Date(endU.getTime() - CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN*60000);

    // fetch login activities
    const {rows, count, uniqueIps, uniqueEmails} = _fetchLoginRows_(startU, endU, triggerName);
    eventsParsed = count;

    // GEO cache/enrich — batch parallel fetch for uncached IPs
    const geoMap = _loadGeoMap_(shGeo);
    const ipsToEnrich = [];
    uniqueIps.forEach(ip => { if (ip && !_isFreshGeo_(geoMap[ip])) ipsToEnrich.push(ip); });
    if (ipsToEnrich.length) {
      const batchResults = _geolocateBatch_(ipsToEnrich);
      const geoEntries = Object.entries(batchResults);
      // Update in-memory map immediately so row-building below sees fresh data
      geoEntries.forEach(([ip, g]) => { geoMap[ip] = g; });
      // Single batch write for all newly resolved IPs
      _batchWriteGeoRows_(shGeo, batchResults);
    }

    // Retry any previously failed geo lookups (up to 5 per sync)
    _retryFailedGeoLookups_(shGeo);

    // OU cache/enrich
    // For large domains use one bulk Directory call; otherwise fall back to per-email.
    if (CONFIG.BULK_OU_LOAD) {
      _bulkLoadAllOUs_(shOU);   // populates __OU_INDEX and __OU_ROW_INDEX in one pass
    } else {
      const emailsToFetch = [];
      uniqueEmails.forEach(email => { if (email && !_isFreshOU_(__ouMap[email])) emailsToFetch.push(email); });
      const ouFetched = [];
      emailsToFetch.forEach(email => {
        const ou = _getOUForEmail_(email);
        if (ou) {
          const obj = { ou, lastSeenISO: new Date().toISOString() };
          __ouMap[email] = obj;
          if (!__OU_INDEX) __OU_INDEX = {};
          __OU_INDEX[String(email).toLowerCase()] = { ou: _normalizeOU_(ou), lastSeenISO: obj.lastSeenISO };
          ouFetched.push({ email, obj });
        }
      });
      if (ouFetched.length) _batchWriteOURows_(shOU, ouFetched);
    }

    // Bind & append (with PRECOMPUTED fields)
    // Apply OU filter — drop events from unmonitored OUs (empty = keep all)
    const filteredRows = rows.filter(r => {
      const ou = (__ouMap[r.email] && __ouMap[r.email].ou) || '';
      return _isMonitoredOU_(ou);
    });
    const out = filteredRows.map(r => {
      const g  = geoMap[r.ip] || {};
      const ou = (__ouMap[r.email] && __ouMap[r.email].ou) || '';

      const parsedNoTZ = _fmtCT_no_tz_(r.ts);
      const hourBucket = _hourBucketNoTZ_(r.ts);
      const outsideUS  = (g.country && String(g.country).toUpperCase() !== 'US') ? true : false;
      const hasGeo     = (_isCoord(g.lat) && _isCoord(g.lon)) ? 'Yes' : 'No';
      const topOU      = _topOU_(ou);

      return [
        _fmtCT(r.ts), r.email, r.eventName, r.ip,
        g.city||'', g.region||'', g.country||'', g.isp||'',
        r.rawJSON, r.key,
        _fmtLatLng_(g.lat, g.lon), g.source||'',
        ou,
        parsedNoTZ, hourBucket, outsideUS, hasGeo, topOU
      ];
    });

    // Key-index deduplication: only append rows whose Event Key is not already known.
    // This avoids reading/rewriting the entire Main sheet on every sync.
    if (out.length) {
      const existingKeys = _loadKeyIndex_();
      const newRows = out.filter(r => {
        const k = r[MAIN_HEADERS.indexOf('Event Key')];
        return k && !existingKeys.has(k);
      });
      if (newRows.length) {
        shMain.getRange(shMain.getLastRow() + 1, 1, newRows.length, MAIN_HEADERS.length).setValues(newRows);
        _appendToKeyIndex_(newRows.map(r => r[MAIN_HEADERS.indexOf('Event Key')]));
        // Fire Outside US alerts for each newly written row
        newRows.forEach(sheetRow => {
          const rowEmail    = sheetRow[1];
          const rowEventName= sheetRow[2];
          const rowIp       = sheetRow[3];
          const rowKey      = sheetRow[9];
          const rowTs       = new Date(sheetRow[0]);
          const g           = geoMap[rowIp] || {};
          const r           = { email: rowEmail, eventName: rowEventName, ip: rowIp, key: rowKey, ts: rowTs };
          if (!_isWhitelisted_(r.email, r.ip)) _maybeAlertOutsideUS_(triggerName, r, g);
        });
      }
      rowsAppended = newRows.length;
    }

    _refreshActiveNow_();
    _refreshSuspicious_(triggerName);
    _checkFailThreshold_(triggerName);

    // Rolling trim (optional immediate trim after each sync)
    if (CONFIG.TRIM_AFTER_SYNC) {
      trimMainRolling();
    }

    // Persist cursor — but only advance on first run if we actually got data.
    // If lastRunISO was absent and we appended nothing, withhold the cursor so
    // the next sync retries the full lookback window instead of a narrow slice.
    const isFirstRun = !lastRunISO;
    if (!isFirstRun || rowsAppended > 0) {
      props.setProperty('lastRunISO', endU.toISOString());
      // Also write actual wall-clock sync time for the map's sync age indicator
      props.setProperty('lastSyncWallTime', new Date().toISOString());
    }

    note = 'Window ' + startU.toISOString() + ' to ' + endU.toISOString() +
           ' | unique IPs: ' + uniqueIps.size + ' | unique emails: ' + uniqueEmails.size +
           (isFirstRun && rowsAppended === 0 ? ' | FIRST RUN / NO ROWS - cursor withheld, will retry' : '');
  } catch (e) {
    note = 'ERROR: ' + (e && e.stack ? e.stack : e);
    throw e;
  } finally {
    _logDiagnostics(triggerName, t0, new Date(), eventsParsed, rowsAppended, note);
  }
}

// ===== Rolling Trim (Main keeps last KEEP_DAYS) ==============================

function trimMainRolling() {
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shArchive = ss.getSheetByName(CONFIG.ARCHIVE);

  const rows = _getRows(shMain); // body only
  if (!rows.length) return;

  const cutoff = new Date(Date.now() - CONFIG.KEEP_DAYS * 24 * 3600000);

  const oldRows = [];
  const keepRows = [];
  for (let i = 0; i < rows.length; i++) {
    const ts = new Date(rows[i][0]); // "Timestamp" (CT ISO with offset)
    if (isNaN(ts)) { keepRows.push(rows[i]); continue; } // keep weird/blank safely
    if (ts < cutoff) oldRows.push(rows[i]); else keepRows.push(rows[i]);
  }

  if (oldRows.length) {
    shArchive.getRange(shArchive.getLastRow() + 1, 1, oldRows.length, MAIN_HEADERS.length).setValues(oldRows);
    _dedupeSheetByKey(shArchive, MAIN_HEADERS, MAIN_HEADERS.indexOf('Event Key'));
  }

  _clearBody(shMain);
  if (keepRows.length) shMain.getRange(2, 1, keepRows.length, MAIN_HEADERS.length).setValues(keepRows);
  _dedupeSheetByKey(shMain, MAIN_HEADERS, MAIN_HEADERS.indexOf('Event Key'));

  _logDiagnostics('trimMainRolling', new Date(), new Date(), rows.length, keepRows.length,
    'Archived=' + oldRows.length + ', Kept=' + keepRows.length + ', Cutoff=' + cutoff.toISOString());
}

// ===== Fetch (AdminReports) ==================================================

function _fetchLoginRows_(startU, endU, triggerName) {
  triggerName = triggerName || 'unknown';
  var rows = [];
  var uniqueIps = new Set();
  var uniqueEmails = new Set();

  // Defensive: never ask for an inverted window
  if (!(startU instanceof Date) || !(endU instanceof Date) || startU >= endU) {
    return {rows: [], count: 0, uniqueIps, uniqueEmails};
  }

  // The API sometimes chokes on bigger windows. We’ll try the requested window,
  // and if we get repeated "Empty response" we auto-shrink the slice.
  var sliceStart = new Date(startU);
  var sliceEnd   = new Date(endU);

  // inner function: fetch one contiguous window with pagination
  function fetchWindow(wStart, wEnd) {
    let token, pageCount = 0, gotAny = false;
    do {
      const params = {
        startTime: wStart.toISOString(),
        endTime:   wEnd.toISOString(),
        maxResults: 500
      };
      if (token) params.pageToken = token;

      const resp = _reportsListSafe_('all', 'login', params); // <- safe retrier
      const items = (resp && resp.items) || [];
      pageCount++;
      if (items.length) {
        gotAny = true;
        for (let i = 0; i < items.length; i++) {
          const a = items[i];
          const ts = new Date(a.id.time);
          let email = (a.actor && a.actor.email) || '';
          const ip = a.ipAddress || '';
          const evs = (a.events || []);
          const uq = a.id && a.id.uniqueQualifier ? String(a.id.uniqueQualifier) : null;

          // For system events (empty actor), extract affected email from parameters
          if (!email && evs.length) {
            for (const ev of evs) {
              const params = ev.parameters || [];
              for (const p of params) {
                if (p.name === 'affected_email_address' || p.name === 'email_address' || p.name === 'target_user') {
                  email = p.value || '';
                  break;
                }
              }
              if (email) break;
            }
          }

          if (ip) uniqueIps.add(ip);
          if (email) uniqueEmails.add(email);

          if (!evs.length) {
            const key0 = _mkKey_(uq || (a.id.time + '|' + email + '|' + ip + '|_'));
            rows.push({ts, email, ip, eventName: 'login_event', key: key0, rawJSON: JSON.stringify(a)});
          } else {
            for (let j = 0; j < evs.length; j++) {
              const evName = evs[j].name || 'login_event';
              const key = _mkKey_((uq ? uq : (a.id.time + '|' + email + '|' + ip)) + '|' + evName);
              rows.push({ts, email, ip, eventName: evName, key, rawJSON: JSON.stringify(a)});
              // Fire immediate alert for password leak events
              if (evName === 'account_disabled_password_leak' && email) {
                _maybeAlertPasswordLeak_(triggerName, email, ts);
              }
            }
          }
        }
      }

      token = resp && resp.nextPageToken;
      // Be polite; avoid tight loops
      if (token) _sleep(150);
    } while (token);

    return gotAny;
  }

  // Try the full window; on repeated empty-response failures the safe wrapper already retries.
  // If still nothing, that might be legit (no events) — BUT some tenants hit "ghost empties".
  // As an extra guard, split the window into smaller chunks and try again.
  try {
    fetchWindow(sliceStart, sliceEnd);
  } catch (e) {
    // If the error was our favorite "Empty response", auto-split into 1h chunks and continue.
    var msg = (e && e.message) ? e.message : String(e);
    if (/Empty response/i.test(msg)) {
      var cursor = new Date(sliceStart);
      while (cursor < sliceEnd) {
        var next = new Date(Math.min(cursor.getTime() + 3600000, sliceEnd.getTime())); // 1h
        try {
          fetchWindow(cursor, next);
        } catch (e2) {
          // Give up on this hour; log and continue so the run completes
          _logDiagnostics('_fetchLoginRows_/hour-skip', cursor, next, 0, 0,
            'Skipped 1h due to: ' + ((e2 && e2.message) ? e2.message : String(e2)));
        }
        cursor = next;
      }
    } else {
      // Non-retryable error → rethrow
      throw e;
    }
  }

  return {rows: rows, count: rows.length, uniqueIps: uniqueIps, uniqueEmails: uniqueEmails};
}


// ===== Active Now (windowed + OU + geo + PRECOMPUTED) =======================

function _refreshActiveNow_(windowMin) {
  const __ouMap = __getOUMap();
  const minutes = Number(windowMin) || CONFIG.ACTIVE_WINDOW_MINUTES;
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shActive = ss.getSheetByName(CONFIG.ACTIVE);
  const shGeo = ss.getSheetByName(CONFIG.GEOCACHE);
  const shOU  = ss.getSheetByName(CONFIG.OU_CACHE);

  const cutoff = new Date(Date.now() - minutes * 60000);

  const mainVals = _getRows(shMain);
  const allObjs = mainVals.map(r => ({
    ts: new Date(r[0]),
    email: r[1],
    name: r[2],
    row: r
  })).filter(x => x.email);

  const windowObjs = allObjs.filter(x => x.ts >= cutoff);

  const byUser = {}; // email -> {first,last,count,sources:{}, latestLoginRow, latestLoginTs}
  for (const x of windowObjs) {
    if (!byUser[x.email]) byUser[x.email] = { first: x.ts, last: x.ts, count: 1, sources: {}, latestLoginRow: null, latestLoginTs: null };
    else {
      if (x.ts < byUser[x.email].first) byUser[x.email].first = x.ts;
      if (x.ts > byUser[x.email].last)  byUser[x.email].last  = x.ts;
      byUser[x.email].count++;
    }
    if (x.name && x.name.indexOf('login') === 0) {
      byUser[x.email].sources.login = (byUser[x.email].sources.login || 0) + 1;
      if (!byUser[x.email].latestLoginTs || x.ts > byUser[x.email].latestLoginTs) {
        byUser[x.email].latestLoginTs = x.ts;
        byUser[x.email].latestLoginRow = x.row;
      }
    }
  }

  if (CONFIG.ACTIVE_INCLUDE_TOKEN) {
    const tokenEvents = _fetchTokenEvents_(cutoff, new Date());
    for (const ev of tokenEvents) {
      if (!byUser[ev.email]) byUser[ev.email] = { first: ev.ts, last: ev.ts, count: 1, sources: {token:1}, latestLoginRow: null, latestLoginTs: null };
      else {
        if (ev.ts < byUser[ev.email].first) byUser[ev.email].first = ev.ts;
        if (ev.ts > byUser[ev.email].last)  byUser[ev.email].last  = ev.ts;
        byUser[ev.email].count++;
        byUser[ev.email].sources.token = (byUser[ev.email].sources.token || 0) + 1;
      }
    }
  }

  const geoMap = _loadGeoMap_(shGeo);
  const ouMap  = _loadOUMap_(shOU);

  const out = Object.keys(byUser).sort().map(email => {
    const u = byUser[email];
    const s = u.sources || {};
    const sourcesList = Object.keys(s).sort().join(',') || 'login';

    let ou = (__ouMap[email] && __ouMap[email].ou) || '';
    let lastIp = '', city = '', region = '', country = '', isp = '', latlng = '', geoSrc = '';

    if (u.latestLoginRow) {
      lastIp = u.latestLoginRow[3] || '';
      city   = u.latestLoginRow[4] || '';
      region = u.latestLoginRow[5] || '';
      country= u.latestLoginRow[6] || '';
      isp    = u.latestLoginRow[7] || '';
      latlng = u.latestLoginRow[10] || '';
      geoSrc = u.latestLoginRow[11] || '';
      if (u.latestLoginRow.length >= MAIN_HEADERS.length) ou = u.latestLoginRow[MAIN_HEADERS.indexOf('Org Unit Path')] || ou;
    } else {
      const fallbackLogin = _latestLoginRowForEmail_(email, allObjs);
      if (fallbackLogin) {
        lastIp = fallbackLogin[3] || '';
        city   = fallbackLogin[4] || '';
        region = fallbackLogin[5] || '';
        country= fallbackLogin[6] || '';
        isp    = fallbackLogin[7] || '';
        latlng = fallbackLogin[10] || '';
        geoSrc = fallbackLogin[11] || '';
        ou     = fallbackLogin[MAIN_HEADERS.indexOf('Org Unit Path')] || ou;
      }
      if (lastIp && (!city && !region && !country && !isp && !latlng)) {
        const g = geoMap[lastIp];
        if (g) {
          city = g.city || ''; region = g.region || ''; country = g.country || ''; isp = g.isp || '';
          latlng = _fmtLatLng_(g.lat, g.lon); geoSrc = g.source || '';
        }
      }
      if (!ou) {
        const liveOu = _getOUForEmail_(email);
        if (liveOu) {
          ou = liveOu;
          const obj = {ou:ou, lastSeenISO:new Date().toISOString()};
          _upsertOURow_(shOU, email, obj);
          __ouMap[email] = obj;
        }
      }
      if (!lastIp && !city && !region && !country && !isp && !latlng) {
        const backfill = _backfillGeoForEmail_(email, ss.getSheetByName(CONFIG.GEOCACHE), geoMap, 180);
        if (backfill) {
          lastIp = backfill.ip || '';
          city   = backfill.city || '';
          region = backfill.region || '';
          country= backfill.country || '';
          isp    = backfill.isp || '';
          latlng = _fmtLatLng_(backfill.lat, backfill.lon);
          geoSrc = backfill.source || '';
        }
      }
    }

    const lastCT = u.last;
    const lastNoTZ   = _fmtCT_no_tz_(lastCT);
    const hourBucket = _hourBucketNoTZ_(lastCT);
    const outsideUS  = (country && String(country).toUpperCase() !== 'US') ? true : false;
    const hasGeo     = (latlng !== '') ? 'Yes' : 'No';

    return [
      email,
      _asTextLiteral_(_resolveOU_(email, (__ouMap[email.toLowerCase()]?.ou ?? (ou || '')))),
      _fmtCT(u.first),
      _fmtCT(u.last),
      sourcesList,
      minutes,
      u.count,
      lastIp, city, region, country, isp, latlng, geoSrc,
      lastNoTZ, hourBucket, outsideUS, hasGeo
    ];
  });

  _clearBody(shActive); _setHeaders(shActive, ACTIVE_HEADERS);
  if (out.length) shActive.getRange(2,1,out.length,ACTIVE_HEADERS.length).setValues(out);
}

function _fetchTokenEvents_(startU, endU) {
  const out = [];
  const params = { startTime: startU.toISOString(), endTime: endU.toISOString(), maxResults: 500 };
  let page;
  do {
    if (page) params.pageToken = page;
    const resp = AdminReports.Activities.list('all', 'token', params);
    const items = (resp && resp.items) || [];
    for (let i = 0; i < items.length; i++) {
      const a = items[i];
      const ts = new Date(a.id.time);
      const email = (a.actor && a.actor.email) || '';
      if (!email) continue;
      out.push({ email, ts });
    }
    page = resp && resp.nextPageToken;
  } while (page);
  return out;
}

function _latestLoginRowForEmail_(email, allObjs) {
  for (let i = allObjs.length - 1; i >= 0; i--) {
    const x = allObjs[i];
    if (x.email === email && x.name && x.name.indexOf('login') === 0) return x.row;
  }
  return null;
}

// ===== Suspicious ============================================================


/**
 * Migrates the Suspicious sheet to add the Alerted column if missing.
 * Safe to run multiple times — only adds the column if it doesn't exist.
 */
function migrateSuspiciousSheet() {
  const ss     = SpreadsheetApp.getActive();
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);
  if (!shSusp) return;

  const lastCol = shSusp.getLastColumn();
  const expectedCols = SUSP_HEADERS.length; // 20

  if (lastCol >= expectedCols) {
    SpreadsheetApp.getActive().toast('Suspicious sheet already up to date.', 'Watchdog', 3);
    return;
  }

  // Add Alerted header
  shSusp.getRange(1, expectedCols).setValue('Alerted');

  // Pad all existing data rows with empty string in the new column
  const lastRow = shSusp.getLastRow();
  if (lastRow > 1) {
    shSusp.getRange(2, expectedCols, lastRow - 1, 1).setValue('');
  }

  SpreadsheetApp.getActive().toast(
    'Added Alerted column to Suspicious sheet. ' + (lastRow - 1) + ' rows updated.',
    'Workspace Watchdog', 5);
}

function _refreshSuspicious_(triggerName) {
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);

  // Auto-migrate: add Alerted column if sheet has old 19-col schema
  if (shSusp && shSusp.getLastRow() >= 1 && shSusp.getLastColumn() < SUSP_HEADERS.length) {
    shSusp.getRange(1, SUSP_HEADERS.length).setValue('Alerted');
    if (shSusp.getLastRow() > 1) {
      shSusp.getRange(2, SUSP_HEADERS.length, shSusp.getLastRow() - 1, 1).setValue('');
    }
  }

  // Load set of event key pairs already alerted — never re-alert the same event
  const alertedKeys = new Set();
  if (shSusp && shSusp.getLastRow() > 1) {
    // Read only cols we need — handle both 19-col (old) and 20-col (new) sheets
    const numCols = Math.min(shSusp.getLastColumn(), SUSP_HEADERS.length);
    const existing = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, numCols).getValues();
    existing.forEach(r => {
      // Alerted is the last column — index 19 (0-based) in new schema
      if (r.length >= 20 && String(r[19]) === 'Yes') {
        alertedKeys.add(String(r[14]) + '_' + String(r[15] || ''));
      }
    });
  }

  // Build retained rows and retainedAlerted set — needed before detection runs
  const existingSusp = _getRows(shSusp);
  const keepCutoff   = new Date(Date.now() - CONFIG.KEEP_DAYS * 24 * 3600000);
  const retainedAlerted = new Set();
  const retained = existingSusp.filter(r => {
    try { return new Date(r[16] || r[0]) >= keepCutoff; } catch(_) { return true; }
  }).map(r => {
    while (r.length < SUSP_HEADERS.length) r.push('');
    return r;
  });
  retained.forEach(r => {
    if (String(r[SUSP_HEADERS.length - 1]) === 'Yes') {
      retainedAlerted.add(String(r[14]) + '_' + String(r[15] || ''));
    }
  });

  const rows = _getRows(shMain).map(r => ({
    ts: new Date(r[0]),
    email: r[1],
    name: r[2],
    ip: r[3],
    city: r[4], region: r[5], country: r[6],
    isp: r[7],
    key: r[9],
    latlng: r[10] || ''
  })).filter(r => r.email);

  const byUser = {};
  rows.forEach(r => { if (!byUser[r.email]) byUser[r.email] = []; byUser[r.email].push(r); });
  Object.keys(byUser).forEach(k => byUser[k].sort((a,b)=>a.ts-b.ts));

  const out = [];

  function _suspTail_(dateObj, reason) {
    const suspNoTZ = _fmtCT_no_tz_(dateObj);
    const hb = _hourBucketNoTZ_(dateObj);
    const severity = (reason === 'Impossible Travel') ? 3
                  : (reason === 'Login Burst') ? 2
                  : (reason === 'Outside US') ? 1
                  : 0;
    return [suspNoTZ, hb, severity];
  }

  // Outside US
  rows.forEach(r => {
    if (r.country && r.country !== 'US') {
      if (_isWhitelisted_(r.email, r.ip)) return; // suppressed
      const tail = _suspTail_(r.ts, 'Outside US');
      const ouAlertKey = String(r.key) + '_';
      const ouAlerted  = _isAlertedPermanently_(ouAlertKey) ? 'Yes' : '';
      out.push([
        _fmtCT(r.ts), r.email, 'Outside US', 'Country=' + r.country,
        '', '', '', '',
        '', '', '', '',
        '', '', r.key, '',
        ...tail, ouAlerted
      ]);
      if (!ouAlerted) _markAlertedPermanently_(ouAlertKey);
    }
  });

  // Bursts
  Object.keys(byUser).forEach(email => {
    const evs = byUser[email].filter(e => e.name && e.name.startsWith('login'));
    for (let i=0;i<evs.length;i++) {
      const start = evs[i].ts;
      let j = i, c = 0;
      while (j < evs.length && (evs[j].ts - start) <= CONFIG.BURST_WINDOW_MIN*60000) { c++; j++; }
      if (c >= CONFIG.BURST_COUNT) {
        if (_isWhitelisted_(email, null)) { i = j - 1; continue; } // suppressed
        const last = evs[j-1];
        const tail = _suspTail_(last.ts, 'Login Burst');
        const burstAlertKey = String(evs[i].key) + '_' + String(last.key || '');
        const burstAlerted  = _isAlertedPermanently_(burstAlertKey) ? 'Yes' : '';
        out.push([
          _fmtCT(last.ts), email, 'Login Burst', c + ' events <= ' + CONFIG.BURST_WINDOW_MIN + ' min',
          '', '', '', '',
          '', '', '', '',
          '', '', evs[i].key, last.key,
          ...tail, burstAlerted
        ]);
        if (!burstAlerted) {
          _maybeAlertLoginBurst_(triggerName, email, c, CONFIG.BURST_WINDOW_MIN, evs[i].ts, last.ts, evs[i].key, last.key);
          _markAlertedPermanently_(burstAlertKey);
        }
        i = j - 1;
      }
    }
  });

  // Impossible travel
  Object.keys(byUser).forEach(email => {
    // Parse lat/lon from combined LatLng string for haversine calculation
  byUser[email].forEach(e => {
    if (e.latlng) {
      const parts = String(e.latlng).split(',');
      e.lat = Number(parts[0]); e.lon = Number(parts[1]);
    } else { e.lat = NaN; e.lon = NaN; }
  });
  const ok = byUser[email].filter(e => e.name === 'login_success' && _isCoord(e.lat) && _isCoord(e.lon));
    for (let i=1;i<ok.length;i++) {
      const a = ok[i-1], b = ok[i];
      const miles = _haversineMi(a.lat,a.lon,b.lat,b.lon);
      const dtH = (b.ts - a.ts)/3600000;
      if (dtH > 0) {
        const mph = miles / dtH;
        if (miles >= CONFIG.IMPOSSIBLE_MIN_MILES && mph >= CONFIG.IMPOSSIBLE_MPH) {
          if (_isWhitelisted_(email, a.ip) || _isWhitelisted_(email, b.ip)) continue; // suppressed
          const details = 'dt=' + dtH.toFixed(2) + 'h, dist=' + miles.toFixed(0) + 'mi, speed≈' + mph.toFixed(0) + ' mph';
          const tail = _suspTail_(b.ts, 'Impossible Travel');
          const travelAlertKey = String(a.key) + '_' + String(b.key || '');
          const travelAlerted  = _isAlertedPermanently_(travelAlertKey) ? 'Yes' : '';
          out.push([
            _fmtCT(b.ts), email, 'Impossible Travel', details,
            a.city||'', a.region||'', a.country||'', _fmtLatLng_(a.lat, a.lon),
            b.city||'', b.region||'', b.country||'', _fmtLatLng_(b.lat, b.lon),
            Number(miles.toFixed(1)), Number(mph.toFixed(0)), a.key, b.key,
            ...tail, travelAlerted
          ]);
          if (!travelAlerted) {
            _maybeAlertImpossibleTravel_(triggerName, email, a, b, miles, mph);
            _markAlertedPermanently_(travelAlertKey);
          }
        }
      }
    }
  });

  // Merge with existing Suspicious rows (retained was built earlier)

  // Combine retained + new detections, then dedup
  // Put out[] BEFORE retained so dedup keeps retained rows (which have Alerted=Yes)
  // when timestamps match — retained rows take priority over newly computed rows
  const combined = out.concat(retained);
  _clearBody(shSusp); _setHeaders(shSusp, SUSP_HEADERS);
  if (combined.length) shSusp.getRange(2,1,combined.length,SUSP_HEADERS.length).setValues(combined);
  _dedupeSheetByKey(shSusp, SUSP_HEADERS, SUSP_HEADERS.indexOf('Timestamp (CT)'));
  _dedupeByComposite_(shSusp, [1,2,3,16,17]); // email+reason+details+keys
}



// ===== Google Chat Alerts =====================================================
//
// Set CHAT_WEBHOOK_URL in Script Properties (never hard-code it).
// All alert types use a 12-hour dedupe cache so the same event never
// fires more than once per half-day regardless of how many syncs run.
//
// Alert types:
//   Outside US    — any login_success or login_failure from outside the US
//   Impossible Travel — two login_success events with physics-defying speed
//   Login Burst   — N logins within a short window for the same user

/**
 * Core webhook sender. Supports plain text or a Google Chat "card" format.
 * Uses simple text format for maximum compatibility with all Chat clients.
 */
function sendChatAlert_(text) {
  const url = PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL');
  if (!url) return; // Silently skip if not configured — never throw during sync

  try {
    const resp = UrlFetchApp.fetch(url, {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify({ text }),
      muteHttpExceptions: true
    });
    const code = resp.getResponseCode();
    if (code < 200 || code >= 300) {
      _logDiagnostics('sendChatAlert_/error', new Date(), new Date(), 0, 0,
        'Webhook HTTP ' + code + ': ' + resp.getContentText().slice(0, 200));
    }
  } catch (e) {
    // Log but never let an alert failure crash a sync
    _logDiagnostics('sendChatAlert_/exception', new Date(), new Date(), 0, 0,
      (e && e.message ? e.message : String(e)));
  }
}

/**
 * Sends an alert only if the same cacheKey hasn't been sent within
 * CHAT_ALERT_DEDUPE_HOURS. Uses Apps Script CacheService (6-hour max per put,
 * so we chain puts for longer TTLs).
 */
function _sendAlertOnce_(cacheKey, text) {
  // Use BOTH Script Properties (persistent) and Cache (fast) for dedupe
  const p   = PropertiesService.getScriptProperties();
  const c   = CacheService.getScriptCache();
  const raw = 'ww_alert_' + String(cacheKey).replace(/[^a-zA-Z0-9_]/g, '_');
  // Use hash to keep key short and avoid collisions from truncation
  const k   = raw.slice(0, 240);
  const now = Date.now();
  const ttlMs  = Math.max(3600000, (CONFIG.CHAT_ALERT_DEDUPE_HOURS || 12) * 3600000);
  const ttlSec = Math.min(21600, Math.floor(ttlMs / 1000));

  // Check cache first (fast)
  if (c.get(k)) {
    _logDiagnostics('alertDedup/cache', new Date(), new Date(), 0, 0,
      'Suppressed (cache): ' + raw.slice(0, 80));
    return;
  }

  // Check Script Properties (persistent, survives cache flush)
  const existing = p.getProperty(k);
  if (existing) {
    try {
      if (now - Number(existing) < ttlMs) {
        _logDiagnostics('alertDedup/props', new Date(), new Date(), 0, 0,
          'Suppressed (props): ' + raw.slice(0, 80));
        // Re-warm cache so next check is fast
        c.put(k, '1', ttlSec);
        return;
      }
    } catch(_) { return; }
  }

  // Not seen — store in both and send
  p.setProperty(k, String(now));
  c.put(k, '1', ttlSec);
  sendChatAlert_(text);
}

/**
 * Guard: returns true if alerts are allowed for this trigger name.
 * When CHAT_ALERT_SCHEDULED_ONLY is true, alerts only fire during
 * scheduledSync — not during installs, backfills, or manual runs.
 */
function _alertsEnabled_(triggerName) {
  if (!PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL')) return false;
  if (CONFIG.CHAT_ALERT_SCHEDULED_ONLY && triggerName !== 'scheduledSync') return false;
  return true;
}

// ── Outside US ────────────────────────────────────────────────────────────────



// ── Failed Login Threshold Alert ──────────────────────────────────────────────

function _checkFailThreshold_(triggerName) {
  if (!CONFIG.CHAT_ALERT_ON_FAIL_THRESHOLD) return;
  if (!_alertsEnabled_(triggerName)) return;

  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  if (!shMain || shMain.getLastRow() <= 1) return;

  const cutoff = new Date(Date.now() - 24 * 3600000);
  const data   = shMain.getRange(2, 1, shMain.getLastRow() - 1, 3).getValues();

  const failCounts = {};
  for (const r of data) {
    const ts     = r[0];
    const email  = String(r[1] || '').toLowerCase();
    const evName = String(r[2] || '');
    if (!email || !ts || new Date(ts) < cutoff) continue;
    if (evName !== 'login_failure') continue;
    failCounts[email] = (failCounts[email] || 0) + 1;
  }

  Object.entries(failCounts).forEach(([email, count]) => {
    if (count < CONFIG.FAIL_THRESHOLD_COUNT) return;
    if (_isWhitelisted_(email, null)) return;

    const cacheKey = 'failthresh_' + email + '_' +
      Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd');

    const msg =
      'Failed Login Threshold Exceeded\n' +
      'User:      ' + email + '\n' +
      'Failures:  ' + count + ' in the last 24 hours\n' +
      'Threshold: ' + CONFIG.FAIL_THRESHOLD_COUNT + '\n' +
      'Note: This may indicate a slow brute-force attack.';

    _sendAlertOnce_(cacheKey, msg);
  });
}

// ── Password Leak Alert ───────────────────────────────────────────────────────

function _maybeAlertPasswordLeak_(triggerName, email, ts) {
  if (!CONFIG.CHAT_ALERT_ON_PASSWORD_LEAK) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(email, null)) return;

  const cacheKey = 'pwleak_' + email + '_' + (ts ? new Date(ts).toISOString().slice(0,10) : '');
  const msg =
    'CRITICAL: Password Leak Detected\n' +
    'User:   ' + email + '\n' +
    'Action: Google has disabled this account due to a detected\n' +
    '        password appearing in a known data breach.\n' +
    'Time:   ' + _fmtCT(ts) + '\n' +
    'Next:   Reset password immediately in Google Admin.';

  _sendAlertOnce_(cacheKey, msg);
}


// ── Permanent Alert Dedup ─────────────────────────────────────────────────────
// Stores alerted event keys permanently in Script Properties.
// Unlike the sheet-based approach, these survive sheet rebuilds and merges.
// Keys are cleaned up after 30 days by _cleanupAlertKeys_().

function _isAlertedPermanently_(key) {
  const p = PropertiesService.getScriptProperties();
  const k = 'ww_alerted_' + String(key).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 200);
  const found = p.getProperty(k) !== null;
  _logDiagnostics('permDedup/check', new Date(), new Date(), found ? 1 : 0, 0,
    (found ? 'SUPPRESSED' : 'NOT FOUND') + ': ' + k.slice(0, 120));
  return found;
}

function _markAlertedPermanently_(key) {
  const p = PropertiesService.getScriptProperties();
  const k = 'ww_alerted_' + String(key).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 200);
  try {
    p.setProperty(k, String(Date.now()));
    _logDiagnostics('permDedup/mark', new Date(), new Date(), 0, 0,
      'MARKED: ' + k.slice(0, 120));
  } catch(e) {
    _logDiagnostics('permDedup/error', new Date(), new Date(), 0, 0,
      'FAILED to mark: ' + k.slice(0, 120) + ' | ' + (e.message || String(e)));
  }
}

function _maybeAlertOutsideUS_(triggerName, r, g) {
  if (!CONFIG.CHAT_ALERT_ON_OUTSIDE_US) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(r.email, r.ip)) return; // suppressed by whitelist

  const country = (g && g.country) ? String(g.country).toUpperCase() : '';
  if (!country || country === 'US') return;

  const ev = String(r.eventName || '');
  if (ev !== 'login_success' && ev !== 'login_failure') return;

  const label  = ev === 'login_success' ? 'SUCCESS' : 'FAILED';
  const isp    = _cleanIsp_(g.isp || '');
  const loc    = [g.city, g.region, g.country].filter(Boolean).join(', ');

  const msg =
    'Outside-US Login ' + label + '\n' +
    'User:     ' + r.email + '\n' +
    'Location: ' + loc + '\n' +
    'IP:       ' + r.ip + (isp ? ' (' + isp + ')' : '') + '\n' +
    'Time:     ' + _fmtCT(r.ts);

  _sendAlertOnce_(r.key + '_outsideus', msg);
}

// ── Impossible Travel ─────────────────────────────────────────────────────────

function _maybeAlertImpossibleTravel_(triggerName, email, a, b, miles, mph) {
  if (!CONFIG.CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(email, a.ip) || _isWhitelisted_(email, b.ip)) return;

  // Use same key format as _refreshSuspicious_ permanent dedup check
  const permKey = String(a.key || '') + '_' + String(b.key || '');
  if (_isAlertedPermanently_(permKey)) return;

  const fromLoc = [a.city, a.region, a.country].filter(Boolean).join(', ') || 'Unknown';
  const toLoc   = [b.city, b.region, b.country].filter(Boolean).join(', ') || 'Unknown';

  const msg =
    'Impossible Travel Detected\n' +
    'User:     ' + email + '\n' +
    'From:     ' + fromLoc + '  -> To: ' + toLoc + '\n' +
    'Distance: ' + Math.round(miles) + ' mi  |  Speed: ~' + Math.round(mph) + ' mph\n' +
    'Time A:   ' + _fmtCT(a.ts) + '\n' +
    'Time B:   ' + _fmtCT(b.ts);

  _markAlertedPermanently_(permKey);
  sendChatAlert_(msg);
}

// ── Login Burst ───────────────────────────────────────────────────────────────

function _maybeAlertLoginBurst_(triggerName, email, count, windowMin, firstTs, lastTs, firstKey, lastKey) {
  if (!CONFIG.CHAT_ALERT_ON_BURST) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(email, null)) return;

  // Use same key format as _refreshSuspicious_ permanent dedup check
  const permKey = String(firstKey || '') + '_' + String(lastKey || '');
  if (_isAlertedPermanently_(permKey)) return;

  const msg =
    'Login Burst Detected\n' +
    'User:   ' + email + '\n' +
    'Events: ' + count + ' logins in <= ' + windowMin + ' minute(s)\n' +
    'From:   ' + _fmtCT(firstTs) + '\n' +
    'To:     ' + _fmtCT(lastTs);

  _markAlertedPermanently_(permKey);
  sendChatAlert_(msg);
}

// ── Test & menu helper ────────────────────────────────────────────────────────


/**
 * Saves chat settings directly — bypasses saveWizardConfig.
 * Called from the Chat Alerts card Save button.
 */
function saveChatSettings(webhookUrl, dedupeHours, onOutsideUS, onTravel, onBurst, scheduledOnly) {
  const p = PropertiesService.getScriptProperties();
  if (webhookUrl && webhookUrl.trim()) {
    p.setProperty('CHAT_WEBHOOK_URL', webhookUrl.trim());
  }
  p.setProperties({
    CHAT_ALERT_DEDUPE_HOURS:         String(Number(dedupeHours) || 12),
    CHAT_ALERT_ON_OUTSIDE_US:        String(!!onOutsideUS),
    CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: String(!!onTravel),
    CHAT_ALERT_ON_BURST:             String(!!onBurst),
    CHAT_ALERT_SCHEDULED_ONLY:       String(!!scheduledOnly)
  }); // No deleteOthers — preserve CHAT_WEBHOOK_URL and other stored properties
  _applyRuntimeConfig_();
  return { ok: true };
}

/**
 * Sends a test Chat message using a URL passed directly from the wizard.
 * Stores the URL in Script Properties and fires a test message.
 */
function testChatAlertWithUrl(webhookUrl) {
  if (!webhookUrl || !webhookUrl.trim()) {
    throw new Error('No webhook URL provided.');
  }
  // Store it first
  PropertiesService.getScriptProperties()
    .setProperty('CHAT_WEBHOOK_URL', webhookUrl.trim());
  _applyRuntimeConfig_();

  // Send test message directly — don't use sendChatAlert_ (it reads from props, race condition)
  const resp = UrlFetchApp.fetch(webhookUrl.trim(), {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify({ text: 'Workspace Watchdog v' + WW_MONITOR_VERSION + ': Chat webhook is working.' }),
    muteHttpExceptions: true
  });
  const code = resp.getResponseCode();
  if (code < 200 || code >= 300) {
    throw new Error('Webhook returned HTTP ' + code + ': ' + resp.getContentText().slice(0, 200));
  }
  return { ok: true };
}

function testChatAlert() {
  const url = PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL');
  if (!url) {
    SpreadsheetApp.getUi().alert(
      'No webhook URL set.',
      'Add CHAT_WEBHOOK_URL to Script Properties first.',
      SpreadsheetApp.getUi().ButtonSet.OK
    );
    return;
  }
  sendChatAlert_('Workspace Watchdog v' + WW_MONITOR_VERSION + ': Google Chat webhook is working.');
  SpreadsheetApp.getActive().toast('Test alert sent.', 'Workspace Watchdog', 5);
}



// ===== Daily Email Digest ====================================================
//
// Sends a morning summary to your Google Chat space via CHAT_WEBHOOK_URL.
// Fires from an hourly trigger but only sends when the current CT hour
// matches CONFIG.DIGEST_HOUR (default 7am). Set DIGEST_ENABLED=true.

function dailyDigest() {
  _applyRuntimeConfig_();

  // Run if Chat digest OR email digest is enabled
  const chatEnabled  = CONFIG.DIGEST_ENABLED;
  const emailEnabled = CONFIG.DIGEST_EMAIL_ENABLED;
  if (!chatEnabled && !emailEnabled) return;

  // Only fire at the configured CT hour
  const hourCT = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'H'));
  if (hourCT !== CONFIG.DIGEST_HOUR) return;

  // Dedupe — only send once per day using Script Properties (Cache max is 6h)
  const p        = PropertiesService.getScriptProperties();
  const dedupKey = 'ww_chat_digest_' + Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd');
  if (p.getProperty(dedupKey)) return;
  p.setProperty(dedupKey, new Date().toISOString());

  try {
    const data = _buildDigestData_();
    // Send Chat message only if Chat digest is enabled and webhook exists
    if (chatEnabled) {
      const url = p.getProperty('CHAT_WEBHOOK_URL');
      if (url) {
        const msg = _buildDigestMessage_();
        sendChatAlert_(msg);
      }
    }
    // Send email if enabled
    if (emailEnabled) {
      _sendDigestEmail_(data);
    }
    _logDiagnostics('dailyDigest', new Date(), new Date(), 0, 0,
      'Digest sent (' + (chatEnabled ? 'Chat' : '') + (chatEnabled && emailEnabled ? ' + ' : '') + (emailEnabled ? 'email' : '') + ').');
  } catch (e) {
    _logDiagnostics('dailyDigest/error', new Date(), new Date(), 0, 0,
      'Digest failed: ' + (e && e.message ? e.message : String(e)));
  }
}

function sendDailyDigestNow() {
  _applyRuntimeConfig_();
  const url = PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL');
  if (!url) {
    SpreadsheetApp.getUi().alert(
      'No webhook configured.',
      'Add CHAT_WEBHOOK_URL to Script Properties first.',
      SpreadsheetApp.getUi().ButtonSet.OK
    );
    return;
  }
  try {
    const data = _buildDigestData_();
    const msg  = _buildDigestMessage_();
    sendChatAlert_(msg);
    _sendDigestEmail_(data);
    SpreadsheetApp.getActive().toast('Digest sent (Chat + email).', 'Workspace Watchdog', 5);
  } catch (e) {
    SpreadsheetApp.getUi().alert('Digest Error',
      e && e.message ? e.message : String(e),
      SpreadsheetApp.getUi().ButtonSet.OK);
  }
}



// ===== Weekly Summary Report ==================================================
//
// Sends a comprehensive weekly email every Monday at CONFIG.DIGEST_HOUR.
// Covers the prior full week (last 7 days) using Main + Archive data.

function weeklyReport() {
  _applyRuntimeConfig_();
  if (!CONFIG.WEEKLY_REPORT_ENABLED) return;
  if (!CONFIG.DIGEST_EMAIL_ENABLED) return;

  // Only fire on Monday
  const dayOfWeek = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'u')); // 1=Mon
  if (dayOfWeek !== 1) return;

  // Only fire at configured hour
  const hourCT = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'H'));
  if (hourCT !== CONFIG.DIGEST_HOUR) return;

  // Dedupe — once per week using Script Properties (Cache max is 6h)
  const p        = PropertiesService.getScriptProperties();
  const dedupKey = 'ww_weekly_report_' + Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-ww');
  if (p.getProperty(dedupKey)) return;
  p.setProperty(dedupKey, new Date().toISOString());

  try {
    const data = _buildWeeklyData_();
    _sendWeeklyEmail_(data);
    _logDiagnostics('weeklyReport', new Date(), new Date(), 0, 0, 'Weekly report sent.');
  } catch(e) {
    _logDiagnostics('weeklyReport/error', new Date(), new Date(), 0, 0,
      'Weekly report failed: ' + (e && e.message ? e.message : String(e)));
  }
}

function sendWeeklyReportNow() {
  _applyRuntimeConfig_();
  try {
    const data = _buildWeeklyData_();
    _sendWeeklyEmail_(data);
    SpreadsheetApp.getActive().toast('Weekly report sent.', 'Workspace Watchdog', 5);
  } catch(e) {
    SpreadsheetApp.getUi().alert('Weekly Report Error',
      e && e.message ? e.message : String(e),
      SpreadsheetApp.getUi().ButtonSet.OK);
  }
}

function _buildWeeklyData_() {
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shArch  = ss.getSheetByName(CONFIG.ARCHIVE);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);

  const now      = new Date();
  const cutoff7d = new Date(now.getTime() - 7 * 24 * 3600000);

  // Combine Main + Archive for full week
  function getRows(sh) {
    if (!sh || sh.getLastRow() <= 1) return [];
    return _getRows(sh).filter(r => new Date(r[0]) >= cutoff7d);
  }
  const allRows = getRows(shMain).concat(getRows(shArch));

  const totalEvents  = allRows.length;
  const successCount = allRows.filter(r => r[2] === 'login_success').length;
  const failCount    = allRows.filter(r => r[2] === 'login_failure').length;
  const outsideCount = allRows.filter(r => r[15] === true).length;
  const uniqueUsers  = new Set(allRows.map(r => r[1]).filter(Boolean)).size;
  const failRate     = (successCount + failCount) > 0
    ? ((failCount / (successCount + failCount)) * 100).toFixed(1) : '0.0';

  // Daily breakdown
  const byDay = {};
  allRows.forEach(r => {
    const day = Utilities.formatDate(new Date(r[0]), CONFIG.TZ, 'EEE M/d');
    if (!byDay[day]) byDay[day] = { s: 0, f: 0, o: 0 };
    if (r[2] === 'login_success') byDay[day].s++;
    else if (r[2] === 'login_failure') byDay[day].f++;
    else byDay[day].o++;
  });

  // Top failed accounts
  const failMap = {};
  allRows.filter(r => r[2] === 'login_failure').forEach(r => {
    if (r[1]) failMap[r[1]] = (failMap[r[1]] || 0) + 1;
  });
  const topFails = Object.entries(failMap).sort((a,b) => b[1]-a[1]).slice(0, 10);

  // Top active users
  const activeMap = {};
  allRows.forEach(r => { if (r[1]) activeMap[r[1]] = (activeMap[r[1]] || 0) + 1; });
  const topActive = Object.entries(activeMap).sort((a,b) => b[1]-a[1]).slice(0, 10);

  // Suspicious events
  const suspRows = shSusp && shSusp.getLastRow() > 1
    ? _getRows(shSusp).filter(r => new Date(r[0]) >= cutoff7d) : [];
  const outsideUS = suspRows.filter(r => r[2] === 'Outside US').length;
  const travel    = suspRows.filter(r => r[2] === 'Impossible Travel').length;
  const bursts    = suspRows.filter(r => r[2] === 'Login Burst').length;

  // Password leak events
  const leakEvents = allRows.filter(r => r[2] === 'account_disabled_password_leak');

  // Top risk users
  // Score risk from full week's data (Main + Archive) rather than Main-only
  let topRisk = [];
  try {
    const weekSuspRows = shSusp && shSusp.getLastRow() > 1
      ? _getRows(shSusp).filter(r => new Date(r[0]) >= cutoff7d) : [];
    const riskMap = {};
    allRows.forEach(r => {
      const email = r[1]; if (!email) return;
      if (!riskMap[email]) riskMap[email] = 0;
      if (r[2] === 'login_failure') riskMap[email] += 5;
      if (r[15] === true) riskMap[email] += 10;
      try {
        const h = Number(Utilities.formatDate(new Date(r[0]), CONFIG.TZ, 'H'));
        if (h >= 0 && h < 5) riskMap[email] += 3;
      } catch(e) {}
    });
    weekSuspRows.forEach(r => {
      const email = r[1]; if (!email) return;
      if (!riskMap[email]) riskMap[email] = 0;
      if (r[2] === 'Impossible Travel') riskMap[email] += 20;
      if (r[2] === 'Login Burst')       riskMap[email] += 15;
    });
    topRisk = Object.entries(riskMap)
      .filter(e => e[1] > 0)
      .sort((a,b) => b[1]-a[1])
      .slice(0, 10)
      .map(e => ({ email: e[0], score: Math.min(100, e[1]) }));
  } catch(e) {}

  const weekStart = Utilities.formatDate(cutoff7d, CONFIG.TZ, 'MMM d');
  const weekEnd   = Utilities.formatDate(now, CONFIG.TZ, 'MMM d, yyyy');

  return {
    weekStart, weekEnd,
    totalEvents, successCount, failCount, outsideCount, uniqueUsers, failRate,
    byDay, topFails, topActive, outsideUS, travel, bursts, leakEvents,
    topRisk, suspRows
  };
}

function _sendWeeklyEmail_(data) {
  const p          = PropertiesService.getScriptProperties();
  const extraTo    = (p.getProperty('DIGEST_EMAIL_TO') || '').trim();
  const ownerEmail = Session.getEffectiveUser().getEmail();
  var to = ownerEmail;
  if (extraTo) to = to + ',' + extraTo;

  const subject = 'Workspace Watchdog Weekly Report — ' + data.weekStart + ' to ' + data.weekEnd;
  const html    = _buildWeeklyHtml_(data);

  GmailApp.sendEmail(to, subject,
    'Please view this email in an HTML-capable client.', {
    htmlBody: html, name: 'Workspace Watchdog'
  });
}

function _buildWeeklyHtml_(d) {
  function statBox(label, value, color) {
    return '<td style="text-align:center;padding:14px 16px;">' +
      '<div style="font-size:30px;font-weight:700;color:' + color + ';line-height:1;">' + value + '</div>' +
      '<div style="font-size:11px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.06em;margin-top:5px;">' + label + '</div>' +
      '</td>';
  }

  function sectionHdr(title) {
    return '<tr><td colspan="2" style="padding:20px 24px 8px;">' +
      '<div style="font-size:11px;font-weight:700;color:#8ab4f8;text-transform:uppercase;letter-spacing:.08em;' +
      'border-bottom:1px solid #2a3f5f;padding-bottom:6px;">' + title + '</div></td></tr>';
  }

  function row2(label, value, clr) {
    clr = clr || '#e8eaed';
    return '<tr><td style="padding:6px 24px;font-size:13px;color:#9aa0a6;width:55%;">' + label + '</td>' +
      '<td style="padding:6px 24px;font-size:13px;font-weight:600;color:' + clr + ';">' + value + '</td></tr>';
  }

  // Daily breakdown table rows
  var dayRows = '';
  Object.keys(d.byDay).forEach(function(day) {
    var b = d.byDay[day];
    var total = b.s + b.f + b.o;
    var rate  = (b.s + b.f) > 0 ? ((b.f / (b.s + b.f)) * 100).toFixed(1) : '0.0';
    var rateClr = rate > 10 ? '#ef5350' : rate > 5 ? '#ff9800' : '#81c995';
    dayRows += '<tr style="border-bottom:1px solid #1e3a5f;">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;width:80px;">' + day + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;text-align:right;">' + total + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#81c995;text-align:right;">' + b.s + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#ef5350;text-align:right;">' + b.f + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;font-weight:600;color:' + rateClr + ';text-align:right;">' + rate + '%</td>' +
      '</tr>';
  });

  // Top fails rows
  var maxFails  = d.topFails.length ? d.topFails[0][1] : 1;
  var failRows = d.topFails.slice(0, 10).map(function(e, i) {
    var clr = e[1] >= 10 ? '#ef5350' : e[1] >= 5 ? '#ff9800' : '#9aa0a6';
    var pct = Math.round((e[1] / maxFails) * 100);
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + (i%2===0?'#152232':'#1a2e45') + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;width:30px;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + e[0] + '</td>' +
      '<td style="padding:7px 12px;font-size:13px;font-weight:700;color:' + clr + ';text-align:right;white-space:nowrap;">' + e[1] + '</td>' +
      '<td style="padding:7px 12px;width:120px;">' +
        '<div style="background:#1e3a5f;border-radius:3px;height:8px;">' +
          '<div style="background:' + clr + ';width:' + pct + '%;height:8px;border-radius:3px;"></div>' +
        '</div>' +
      '</td>' +
      '</tr>';
  }).join('');

  // Top active rows
  var activeRows = d.topActive.slice(0, 10).map(function(e, i) {
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + (i%2===0?'#152232':'#1a2e45') + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + e[0] + '</td>' +
      '<td style="padding:7px 12px;font-size:13px;font-weight:700;color:#8ab4f8;text-align:right;">' + e[1] + '</td>' +
      '</tr>';
  }).join('');

  // Risk rows
  var riskRows = d.topRisk.map(function(u, i) {
    var rc  = u.score >= 50 ? '#ef5350' : u.score >= 20 ? '#ff9800' : '#81c995';
    var rl  = u.score >= 50 ? 'HIGH' : u.score >= 20 ? 'MED' : 'LOW';
    var bg  = i % 2 === 0 ? '#152232' : '#1a2e45';
    var pct = u.score;
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + bg + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;width:30px;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + u.email + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;font-weight:700;color:' + rc + ';text-align:right;white-space:nowrap;">' + u.score + '/100</td>' +
      '<td style="padding:7px 12px;width:120px;">' +
        '<div style="background:#1e3a5f;border-radius:3px;height:8px;">' +
          '<div style="background:' + rc + ';width:' + pct + '%;height:8px;border-radius:3px;"></div>' +
        '</div>' +
        '<div style="font-size:10px;color:' + rc + ';margin-top:2px;">' + rl + '</div>' +
      '</td>' +
      '</tr>';
  }).join('');

  var leakHtml = d.leakEvents.length
    ? '<tr style="background:#2a1a1a;"><td colspan="2" style="padding:10px 24px;">' +
      '<span style="color:#ef5350;font-weight:700;">&#9888; ' + d.leakEvents.length + ' password leak event(s) detected this week. Check affected accounts immediately.</span>' +
      '</td></tr>' : '';

  return [
    '<!DOCTYPE html><html><head><meta charset="UTF-8"></head>',
    '<body style="margin:0;padding:0;background:#0f1923;font-family:Arial,sans-serif;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1923;padding:24px 0;">',
    '<tr><td align="center">',
    '<table width="640" cellpadding="0" cellspacing="0" style="background:#152232;border-radius:8px;overflow:hidden;max-width:640px;">',

    // Header
    '<tr><td style="background:#1a2e45;padding:20px 24px;">',
    '<div style="font-size:11px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px;">Workspace Watchdog</div>',
    '<div style="font-size:24px;font-weight:700;color:#e8eaed;">Weekly Security Report</div>',
    '<div style="font-size:12px;color:#9aa0a6;margin-top:4px;">' + d.weekStart + ' &mdash; ' + d.weekEnd + '</div>',
    '</td></tr>',

    // Password leak warning (if any)
    leakHtml ? '<tr><td><table width="100%" cellpadding="0" cellspacing="0">' + leakHtml + '</table></td></tr>' : '',

    // Stat boxes row 1
    '<tr><td style="padding:20px 24px 8px;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Total Events',  d.totalEvents,  '#8ab4f8'),
    statBox('Successful',    d.successCount, '#81c995'),
    statBox('Failed',        d.failCount,    d.failCount > 0 ? '#ef5350' : '#81c995'),
    statBox('Fail Rate',     d.failRate + '%', parseFloat(d.failRate) > 10 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',

    // Stat boxes row 2
    '<tr><td style="padding:0 24px 8px;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Outside US',   d.outsideCount,  d.outsideCount > 0 ? '#ff9800' : '#81c995'),
    statBox('Unique Users', d.uniqueUsers,   '#8ab4f8'),
    statBox('Susp Events',  d.outsideUS + d.travel + d.bursts, (d.outsideUS+d.travel+d.bursts) > 0 ? '#ff9800' : '#81c995'),
    statBox('Pass Leaks',   d.leakEvents.length, d.leakEvents.length > 0 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',

    // Suspicious breakdown
    '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
    sectionHdr('Suspicious Activity'),
    row2('Outside US Logins',  d.outsideUS,  d.outsideUS  > 0 ? '#ff9800' : '#81c995'),
    row2('Impossible Travel',  d.travel,     d.travel     > 0 ? '#ef5350' : '#81c995'),
    row2('Login Bursts',       d.bursts,     d.bursts     > 0 ? '#ff9800' : '#81c995'),
    '</table></td></tr>',

    // Daily breakdown
    '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
    sectionHdr('Daily Breakdown'),
    '</table>',
    '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
    '<tr style="background:#1e3a5f;">',
    '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Day</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Total</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#81c995;text-align:right;">Success</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#ef5350;text-align:right;">Failed</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Fail Rate</th>',
    '</tr>',
    dayRows,
    '</table></td></tr>',

    // Top failed logins
    d.topFails.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
      sectionHdr('Top Failed Login Accounts'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Failures</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:120px;">Distribution</th>',
      '</tr>', failRows, '</table></td></tr>'
    ].join('') : '',

    // Top active users
    d.topActive.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
      sectionHdr('Most Active Users'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Logins</th>',
      '</tr>', activeRows, '</table></td></tr>'
    ].join('') : '',

    // Top risk users
    d.topRisk.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
      sectionHdr('Top Risk Users'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Score</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:120px;">Level</th>',
      '</tr>', riskRows, '</table></td></tr>'
    ].join('') : '',

    // Footer
    '<tr><td style="padding:20px 24px;border-top:1px solid #1e3a5f;">',
    '<div style="font-size:11px;color:#5f6368;text-align:center;">',
    'Workspace Watchdog Weekly Report &mdash; Dawson Education Service Cooperative<br>',
    'Generated automatically every Monday morning. Do not reply to this email.',
    '</div></td></tr>',

    '</table></td></tr></table></body></html>'
  ].join('');
}

// ── HTML Email Digest ─────────────────────────────────────────────────────────

function _buildDigestHtml_(data) {
  const d = data;
  const failColor   = d.failCount > 0   ? '#ef5350' : '#81c995';
  const outsideColor= d.outsideCount > 0 ? '#ff9800' : '#81c995';
  const suspColor   = (d.outsideUS + d.travel + d.bursts) > 0 ? '#ff9800' : '#81c995';

  function statBox(label, value, color) {
    return '<td style="text-align:center;padding:12px 16px;">' +
      '<div style="font-size:26px;font-weight:700;color:' + color + ';line-height:1;">' + value + '</div>' +
      '<div style="font-size:11px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">' + label + '</div>' +
      '</td>';
  }

  function sectionHeader(title) {
    return '<tr><td colspan="2" style="padding:20px 24px 8px;">' +
      '<div style="font-size:11px;font-weight:700;color:#8ab4f8;text-transform:uppercase;letter-spacing:.08em;' +
      'border-bottom:1px solid #2a3f5f;padding-bottom:6px;">' + title + '</div></td></tr>';
  }

  function dataRow(label, value, valueColor) {
    valueColor = valueColor || '#e8eaed';
    return '<tr>' +
      '<td style="padding:6px 24px;font-size:13px;color:#9aa0a6;width:55%;">' + label + '</td>' +
      '<td style="padding:6px 24px;font-size:13px;font-weight:600;color:' + valueColor + ';">' + value + '</td>' +
      '</tr>';
  }

  // Suspicious events rows
  var suspRows = '';
  if (d.suspRecent && d.suspRecent.length) {
    d.suspRecent.slice(0, 5).forEach(function(r) {
      var reasonColor = r[2] === 'Login Burst' ? '#ff9800'
                      : r[2] === 'Impossible Travel' ? '#ef5350' : '#ff9800';
      suspRows +=
        '<tr style="border-bottom:1px solid #1e3a5f;">' +
        '<td style="padding:6px 12px;font-size:12px;color:#9aa0a6;">' + String(r[0]).slice(0,16) + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + (r[1]||'') + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;font-weight:600;color:' + reasonColor + ';">' + (r[2]||'') + '</td>' +
        '</tr>';
    });
  }

  // Top fails rows
  var failRows = '';
  if (d.topFails && d.topFails.length) {
    d.topFails.forEach(function(entry) {
      failRows +=
        '<tr style="border-bottom:1px solid #1e3a5f;">' +
        '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + entry[0] + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;font-weight:600;color:#ef5350;">' + entry[1] + ' failed</td>' +
        '</tr>';
    });
  }

  // Top risk rows
  var riskRows = '';
  if (d.topRisk && d.topRisk.length) {
    d.topRisk.forEach(function(u) {
      var rc = u.score >= 50 ? '#ef5350' : u.score >= 20 ? '#ff9800' : '#81c995';
      var rl = u.score >= 50 ? 'HIGH' : u.score >= 20 ? 'MED' : 'LOW';
      riskRows +=
        '<tr style="border-bottom:1px solid #1e3a5f;">' +
        '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + u.email + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;font-weight:600;color:' + rc + ';">' + u.score + '/100 &mdash; ' + rl + '</td>' +
        '</tr>';
    });
  }

  function delta(dir) {
    if (!d.comparison || !CONFIG.DIGEST_COMPARISON) return '';
    var diff = d.comparison[dir];
    if (diff === 0) return '<span style="font-size:10px;color:#9aa0a6;"> &#8212;</span>';
    var better = (dir === 'failCount' || dir === 'failRate' || dir === 'outsideCount') ? diff < 0 : diff > 0;
    var clr = better ? '#81c995' : '#ef5350';
    var arr = diff > 0 ? '&#9650;' : '&#9660;';
    return '<div style="font-size:10px;color:' + clr + ';margin-top:2px;">' + arr + ' ' + (diff > 0 ? '+' : '') + diff + ' vs yesterday</div>';
  }

  var html = [
    '<!DOCTYPE html><html><head><meta charset="UTF-8">',
    '<title>Workspace Watchdog Daily Digest</title></head>',
    '<body style="margin:0;padding:0;background:#0f1923;font-family:Arial,sans-serif;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1923;padding:24px 0;">',
    '<tr><td align="center">',
    '<table width="620" cellpadding="0" cellspacing="0" style="background:#152232;border-radius:8px;overflow:hidden;max-width:620px;">',

    // Header
    '<tr><td style="background:#1a2e45;padding:20px 24px;">',
    '<div style="font-size:11px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px;">Workspace Watchdog</div>',
    '<div style="font-size:22px;font-weight:700;color:#e8eaed;">Daily Security Digest</div>',
    '<div style="font-size:12px;color:#9aa0a6;margin-top:4px;">' + d.date + '</div>',
    '</td></tr>',

    // Stat boxes
    '<tr><td style="padding:20px 24px 0;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;">',
    '<tr>',
    statBox('Total Events',  d.totalEvents  + (d.comparison ? delta('totalEvents') : ''),   '#8ab4f8'),
    statBox('Successful',    d.successCount + (d.comparison ? delta('successCount') : ''),  '#81c995'),
    statBox('Failed',        d.failCount    + (d.comparison ? delta('failCount') : ''),     failColor),
    statBox('Fail Rate',     d.failRate + '%' + (d.comparison ? delta('failRate') : ''),      d.failRate > 10 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',

    // Second stat row
    '<tr><td style="padding:12px 24px 0;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;">',
    '<tr>',
    statBox('Outside US',   d.outsideCount,  outsideColor),
    statBox('Unique Users', d.uniqueUsers,   '#8ab4f8'),
    statBox('Active Now',   d.activeCount,   '#8ab4f8'),
    statBox('Suspicious',   d.outsideUS + d.travel + d.bursts, suspColor),
    '</tr></table></td></tr>',

    // Suspicious breakdown
    '<tr><td>',
    '<table width="100%" cellpadding="0" cellspacing="0">',
    sectionHeader('Suspicious Activity (Last 24 Hours)'),
    dataRow('Outside US Logins',   d.outsideUS,  d.outsideUS > 0  ? '#ff9800' : '#81c995'),
    dataRow('Impossible Travel',   d.travel,     d.travel > 0     ? '#ef5350' : '#81c995'),
    dataRow('Login Bursts',        d.bursts,     d.bursts > 0     ? '#ff9800' : '#81c995'),
    '</table></td></tr>',

    // Suspicious events table
    d.suspRecent && d.suspRecent.length ? [
      '<tr><td>',
      '<table width="100%" cellpadding="0" cellspacing="0">',
      sectionHeader('Recent Suspicious Events'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Time</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">User</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Reason</th>',
      '</tr>',
      suspRows,
      '</table></td></tr>'
    ].join('') : '',

    // Top failed logins
    d.topFails && d.topFails.length ? [
      '<tr><td>',
      '<table width="100%" cellpadding="0" cellspacing="0">',
      sectionHeader('Top Failed Login Accounts'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Account</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Failures</th>',
      '</tr>',
      failRows,
      '</table></td></tr>'
    ].join('') : '',

    // Rising risk users
    d.risingRisk && d.risingRisk.length ? [
      '<tr><td>',
      '<table width="100%" cellpadding="0" cellspacing="0">',
      sectionHeader('Rising Risk This Week'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Account</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Change</th>',
      '</tr>',
      (function() {
        var rows = '';
        d.risingRisk.forEach(function(u) {
          rows += '<tr style="border-bottom:1px solid #1e3a5f;">' +
            '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + u.email + '</td>' +
            '<td style="padding:6px 12px;font-size:12px;font-weight:600;color:#ef5350;">' +
            u.prev + ' &#8594; ' + u.score + ' <span style="color:#ff9800;">(+' + u.diff + ')</span></td>' +
            '</tr>';
        });
        return rows;
      })(),
      '</table></td></tr>'
    ].join('') : '',

    // Top risk users
    d.topRisk && d.topRisk.length ? [
      '<tr><td>',
      '<table width="100%" cellpadding="0" cellspacing="0">',
      sectionHeader('Top Risk Users (Last 7 Days)'),
      '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;">',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Account</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Risk Score</th>',
      '</tr>',
      riskRows,
      '</table></td></tr>'
    ].join('') : '',

    // Footer
    '<tr><td style="padding:20px 24px;border-top:1px solid #1e3a5f;">',
    '<div style="font-size:11px;color:#5f6368;text-align:center;">',
    'Workspace Watchdog &mdash; Dawson Education Service Cooperative<br>',
    'This digest was generated automatically. Do not reply to this email.',
    '</div></td></tr>',

    '</table></td></tr></table></body></html>'
  ].join('');

  return html;
}

/**
 * Sends the HTML email digest to the script owner and any configured recipients.
 */
function _sendDigestEmail_(data) {
  const p           = PropertiesService.getScriptProperties();
  const emailEnabled = p.getProperty('DIGEST_EMAIL_ENABLED');
  const extraTo     = (p.getProperty('DIGEST_EMAIL_TO') || '').trim();
  const ownerEmail  = Session.getEffectiveUser().getEmail();

  if (emailEnabled === 'false') return;
  try {
    var html    = _buildDigestHtml_(data);
    var subject = 'Workspace Watchdog Digest - ' + data.date;
    var to      = ownerEmail;
    if (extraTo) to = to + ',' + extraTo;
    GmailApp.sendEmail(to, subject, 'Please view this email in an HTML-capable client.', {
      htmlBody: html,
      name: 'Workspace Watchdog'
    });
  } catch(e) {
    _logDiagnostics('digestEmail/error', new Date(), new Date(), 0, 0,
      'Email digest failed: ' + (e && e.message ? e.message : String(e)));
  }
}

function _buildDigestData_() {
  const ss       = SpreadsheetApp.getActive();
  const shMain   = ss.getSheetByName(CONFIG.MAIN);
  const shSusp   = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const shActive = ss.getSheetByName(CONFIG.ACTIVE);

  const cutoff24h = new Date(Date.now() - 24 * 3600000);
  const mainRows  = _getRows(shMain);
  const recent    = mainRows.filter(r => new Date(r[0]) >= cutoff24h);

  const totalEvents  = recent.length;
  const successCount = recent.filter(r => r[2] === 'login_success').length;
  const failCount    = recent.filter(r => r[2] === 'login_failure').length;
  const outsideCount = recent.filter(r => r[15] === true).length;
  const uniqueUsers  = new Set(recent.map(r => r[1])).size;
  const failRate     = (successCount + failCount) > 0
    ? ((failCount / (successCount + failCount)) * 100).toFixed(1) : '0.0';

  const failMap = {};
  recent.filter(r => r[2] === 'login_failure').forEach(r => {
    failMap[r[1]] = (failMap[r[1]] || 0) + 1;
  });
  const topFails = Object.entries(failMap).sort((a,b) => b[1]-a[1]).slice(0, 5);

  const suspRows   = _getRows(shSusp);
  const suspRecent = suspRows.filter(r => new Date(r[0]) >= cutoff24h);
  const outsideUS  = suspRecent.filter(r => r[2] === 'Outside US').length;
  const travel     = suspRecent.filter(r => r[2] === 'Impossible Travel').length;
  const bursts     = suspRecent.filter(r => r[2] === 'Login Burst').length;

  const activeRows    = _getRows(shActive);
  const activeCount   = activeRows.length;
  const activeOutside = activeRows.filter(r => r[16] === true).length;

  let topRisk = [];
  try { topRisk = getTopRiskUsers(3).filter(u => u.score > 0); } catch(e) {}

  // Find rising risk users — score up 15+ pts vs previous week
  const risingRisk = [];
  try {
    topRisk.forEach(function(u) {
      const trend = getUserRiskTrend(u.email);
      if (trend && trend.length >= 2) {
        const prev = trend[trend.length - 2].score;
        const curr = trend[trend.length - 1].score;
        if (curr - prev >= 15) risingRisk.push({ email: u.email, score: curr, prev: prev, diff: curr - prev });
      }
    });
  } catch(e) {}

  // ── Digest comparison — load yesterday's snapshot ────────────────────────
  const p = PropertiesService.getScriptProperties();
  let yesterday = null;
  try {
    const snap = p.getProperty('DIGEST_SNAPSHOT');
    if (snap) yesterday = JSON.parse(snap);
  } catch(e) {}

  // Store today's snapshot for tomorrow's comparison
  try {
    p.setProperty('DIGEST_SNAPSHOT', JSON.stringify({
      date: Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd'),
      totalEvents, successCount, failCount,
      outsideCount, failRate: parseFloat(failRate)
    }));
  } catch(e) {}

  // Only use snapshot if it's from yesterday
  let comparison = null;
  if (yesterday) {
    const yesterdayDate = Utilities.formatDate(
      new Date(Date.now() - 24*3600000), CONFIG.TZ, 'yyyy-MM-dd');
    if (yesterday.date === yesterdayDate) {
      comparison = {
        totalEvents:  totalEvents  - yesterday.totalEvents,
        successCount: successCount - yesterday.successCount,
        failCount:    failCount    - yesterday.failCount,
        outsideCount: outsideCount - yesterday.outsideCount,
        failRate:     (parseFloat(failRate) - yesterday.failRate).toFixed(1)
      };
    }
  }

  return {
    date: Utilities.formatDate(new Date(), CONFIG.TZ, 'MMM d, yyyy - h:mm a z'),
    totalEvents, successCount, failCount, outsideCount, uniqueUsers, failRate,
    topFails, suspRecent, outsideUS, travel, bursts,
    activeCount, activeOutside, topRisk, risingRisk, comparison
  };
}

function _buildDigestMessage_() {
  const d = _buildDigestData_();

  let msg = 'Workspace Watchdog Daily Digest - ' + d.date + '\n';
  msg += '\n*Last 24 Hours*\n';
  msg += 'Total Events: ' + d.totalEvents + '\n';
  msg += 'Successful: ' + d.successCount + '   Failed: ' + d.failCount + '   Fail Rate: ' + d.failRate + '%\n';
  msg += 'Outside US: ' + d.outsideCount + '   Unique Users: ' + d.uniqueUsers + '\n';

  msg += '\n*Suspicious Activity*\n';
  msg += 'Outside US: ' + d.outsideUS + '\n';
  msg += 'Impossible Travel: ' + d.travel + '\n';
  msg += 'Login Bursts: ' + d.bursts + '\n';

  if (d.suspRecent.length) {
    msg += '\n*Recent Suspicious Events*\n';
    d.suspRecent.slice(0, 5).forEach(r => {
      msg += String(r[0]).slice(0,16) + ' | ' + r[1] + ' | ' + r[2] + '\n';
    });
  }

  if (d.topFails.length) {
    msg += '\n*Top Failed Login Accounts*\n';
    d.topFails.forEach(([email, n]) => {
      msg += email + ': ' + n + ' failed attempt' + (n !== 1 ? 's' : '') + '\n';
    });
  }

  msg += '\n*Active Now*\n';
  msg += 'Active users: ' + d.activeCount + '\n';
  if (d.activeOutside > 0) msg += 'Active outside US: ' + d.activeOutside + '\n';

  if (d.topRisk.length) {
    msg += '\n*Top Risk Users (Last 7 Days)*\n';
    d.topRisk.forEach(u => {
      const bar = u.score >= 50 ? 'HIGH' : u.score >= 20 ? 'MED' : 'LOW';
      msg += u.email + ': ' + u.score + '/100 [' + bar + ']\n';
    });
  }

  if (d.risingRisk && d.risingRisk.length) {
    msg += '\n*Rising Risk (Up 15+ pts This Week)*\n';
    d.risingRisk.forEach(u => {
      msg += u.email + ': ' + u.prev + ' -> ' + u.score + ' (+' + u.diff + ')\n';
    });
  }

  return msg;
}


// ===== IP Reputation Lookup (AbuseIPDB) ======================================
//
// Checks an IP against AbuseIPDB's free API. Results are cached in
// Script Properties for IP_REP_CACHE_DAYS to avoid redundant API calls.
// Set ABUSEIPDB_KEY in Script Properties (free key at abuseipdb.com).
// Called from getLiveMapData backend and optionally from getSuspiciousMapData.

/**
 * Looks up IP reputation. Returns:
 *   { score, isVpn, isTor, usageType, domain, flagged }
 *   or null if lookup failed / not enabled.
 */
function checkIPReputation(ip) {
  if (!CONFIG.IP_REP_ENABLED) return null;
  if (!ip) return null;

  const key = PropertiesService.getScriptProperties().getProperty('ABUSEIPDB_KEY');
  if (!key) return null;

  // Check cache first — stored in Script Properties as IP_REP:{ip}
  const cacheKey = 'IP_REP:' + ip;
  const cached   = PropertiesService.getScriptProperties().getProperty(cacheKey);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      // Validate cache age
      if (parsed._ts && (Date.now() - parsed._ts) < CONFIG.IP_REP_CACHE_DAYS * 86400000) {
        return parsed;
      }
    } catch (_) {}
  }

  try {
    const url  = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' +
                 encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';
    const resp = UrlFetchApp.fetch(url, {
      headers: { 'Key': key, 'Accept': 'application/json' },
      muteHttpExceptions: true
    });

    if (resp.getResponseCode() !== 200) return null;

    const j    = JSON.parse(resp.getContentText() || '{}');
    const d    = (j && j.data) ? j.data : null;
    if (!d) return null;

    const result = {
      score:     d.abuseConfidenceScore || 0,
      isVpn:     !!(d.usageType && /vpn|proxy|hosting/i.test(d.usageType)),
      isTor:     !!d.isTor,
      usageType: d.usageType || '',
      domain:    d.domain    || '',
      country:   d.countryCode || '',
      reports:   d.totalReports || 0,
      flagged:   (d.abuseConfidenceScore || 0) >= CONFIG.IP_REP_MIN_SCORE,
      _ts:       Date.now()
    };

    // Cache result — use Script Properties (survives across executions)
    PropertiesService.getScriptProperties().setProperty(cacheKey, JSON.stringify(result));
    return result;

  } catch (e) {
    return null;
  }
}

/**
 * Batch reputation check for an array of IPs.
 * Returns { ip: reputationObject } for all resolved IPs.
 * Respects rate limits — AbuseIPDB free tier allows 1000/day.
 */
function checkIPReputationBatch(ips) {
  const results = {};
  if (!CONFIG.IP_REP_ENABLED || !ips || !ips.length) return results;
  for (const ip of ips) {
    const r = checkIPReputation(ip);
    if (r) results[ip] = r;
    _sleep(100); // be polite to rate limits
  }
  return results;
}

/**
 * Called from LiveMap.html detail panel via google.script.run.
 * Returns reputation data for a single IP, safe to call from client.
 */
function getIPReputation(ip) {
  _applyRuntimeConfig_();
  return checkIPReputation(ip);
}

/**
 * Clears all cached IP reputation data from Script Properties.
 * Useful if you want a fresh lookup after updating ABUSEIPDB_KEY.
 */
function clearIPReputationCache() {
  const p    = PropertiesService.getScriptProperties();
  const all  = p.getKeys();
  let cleared = 0;
  all.forEach(k => { if (k.startsWith('IP_REP:')) { p.deleteProperty(k); cleared++; } });
  SpreadsheetApp.getActive().toast(
    'Cleared ' + cleared + ' cached IP reputation entr' + (cleared === 1 ? 'y' : 'ies') + '.',
    'Workspace Watchdog', 5
  );
}

// ===== Suspicious Event Whitelist ============================================
//
// Entries are stored in Script Properties as SUSPICIOUS_WHITELIST —
// a newline or comma-separated list of email addresses and/or IP addresses.
// Events matching a whitelisted email or IP are silently dropped from the
// Suspicious sheet and suppressed from Chat alerts.
// Main sheet data is never affected — history is always preserved.

var __WHITELIST = null; // { emails: Set, ips: Set } — cached per execution

/**
 * Loads and parses the whitelist from Script Properties.
 * Returns { emails: Set<string>, ips: Set<string> }
 */
function _loadWhitelist_() {
  if (__WHITELIST) return __WHITELIST;

  const raw = PropertiesService.getScriptProperties()
    .getProperty('SUSPICIOUS_WHITELIST') || '';

  const emails = new Set();
  const ips    = new Set();

  raw.split(/[\n\r,]+/).forEach(entry => {
    const e = entry.trim().toLowerCase();
    if (!e) return;
    // Simple heuristic: if it contains '@' it's an email, otherwise treat as IP
    if (e.includes('@')) {
      emails.add(e);
    } else {
      ips.add(e);
    }
  });

  __WHITELIST = { emails, ips };
  return __WHITELIST;
}

/**
 * Returns true if the email or IP is on the whitelist.
 * Either parameter can be omitted/empty.
 */
function _isWhitelisted_(email, ip) {
  const wl = _loadWhitelist_();
  if (email && wl.emails.has(String(email).toLowerCase().trim())) return true;
  if (ip    && wl.ips.has(String(ip).trim()))                      return true;
  return false;
}

/**
 * Saves a new whitelist from the wizard form.
 * Accepts a newline-separated string of emails and IPs.
 * Returns { ok, emailCount, ipCount }
 */
function saveWhitelist(raw) {
  const entries = String(raw || '').replace(/,/g, '\n').split('\n').map(e => e.trim()).filter(Boolean);
  PropertiesService.getScriptProperties()
    .setProperty('SUSPICIOUS_WHITELIST', entries.join('\n'));

  // Reset cache so next sync picks up the new list
  __WHITELIST = null;

  const emails = entries.filter(e => e.includes('@')).length;
  const ips    = entries.length - emails;
  return { ok: true, emailCount: emails, ipCount: ips };
}

/**
 * Returns the current whitelist as a newline-separated string for the wizard.
 */

/**
 * Returns the current MAP_ALLOWED_USERS list.
 * Called from the Setup Wizard.
 */
function getMapAllowedUsers() {
  return PropertiesService.getScriptProperties().getProperty('MAP_ALLOWED_USERS') || '';
}

/**
 * Saves the MAP_ALLOWED_USERS list.
 * Called from the Setup Wizard.
 */
function saveMapAllowedUsers(raw) {
  const cleaned = (raw || '').split(/[,\n]/)
    .map(function(e) { return e.trim().toLowerCase(); })
    .filter(Boolean)
    .join('\n');
  PropertiesService.getScriptProperties().setProperty('MAP_ALLOWED_USERS', cleaned);
  return { ok: true, count: cleaned ? cleaned.split('\n').length : 0 };
}

function getWhitelist() {
  return PropertiesService.getScriptProperties()
    .getProperty('SUSPICIOUS_WHITELIST') || '';
}

/**
 * Called from LiveMap detail panel — appends a single email or IP to the
 * whitelist without overwriting existing entries.
 * Uses dummy examples in UI: user@domain.com or 192.168.1.1
 */

/**
 * Removes a single entry from the whitelist.
 * Called from the Live Map whitelist manager.
 */
function removeFromWhitelist(entry) {
  if (!entry) return { ok: false };
  const p   = PropertiesService.getScriptProperties();
  const raw = p.getProperty('SUSPICIOUS_WHITELIST') || '';
  const entries = raw.split(/[\n,]/).map(e => e.trim().toLowerCase()).filter(Boolean);
  const cleaned = entries.filter(e => e !== String(entry).trim().toLowerCase());
  p.setProperty('SUSPICIOUS_WHITELIST', cleaned.join('\n'));
  return { ok: true, remaining: cleaned.length };
}

function addToWhitelistFromMap(entry) {
  if (!entry || !String(entry).trim()) return { ok: false, message: 'Empty entry.' };
  entry = String(entry).trim().toLowerCase();

  const p   = PropertiesService.getScriptProperties();
  const raw = p.getProperty('SUSPICIOUS_WHITELIST') || '';
  const existing = raw.replace(/,/g, '\n').split('\n')
    .map(function(e) { return e.trim().toLowerCase(); })
    .filter(Boolean);

  if (existing.indexOf(entry) >= 0) {
    return { ok: true, message: entry + ' already in whitelist.' };
  }

  existing.push(entry);
  p.setProperty('SUSPICIOUS_WHITELIST', existing.join('\n'));

  // Reset in-memory cache so next sync picks up the change
  __WHITELIST = null;

  return { ok: true, message: entry + ' added to whitelist.' };
}

// ===== OU Filter =============================================================

/**
 * Returns true if the given OU path should be monitored.
 * CONFIG.MONITOR_OUS is a comma-separated list of OU paths, e.g. "/Staff,/Admins".
 * Subtree matching: "/Staff" also accepts "/Staff/Teachers", "/Staff/Subs", etc.
 * An empty MONITOR_OUS means monitor ALL users.
 */
function _isMonitoredOU_(ou) {
  if (!CONFIG.MONITOR_OUS || !String(CONFIG.MONITOR_OUS).trim()) return true;
  const targets = String(CONFIG.MONITOR_OUS).split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  if (!targets.length) return true;
  const resolved = String(ou || '').toLowerCase();
  return targets.some(t => resolved === t || resolved.startsWith(t + '/'));
}

/**
 * Returns a list of all distinct OU paths currently in OUCache,
 * sorted alphabetically. Called by the wizard to populate the OU picker.
 */
function getMonitorableOUs() {
  _applyRuntimeConfig_();
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.OU_CACHE);
  if (!sh || sh.getLastRow() <= 1) return { ous: [], current: CONFIG.MONITOR_OUS || '' };

  const vals = sh.getRange(2, 1, sh.getLastRow() - 1, sh.getLastColumn()).getValues();
  const header = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0];
  const cOU = header.indexOf('OrgUnitPath');
  if (cOU < 0) return { ous: [], current: CONFIG.MONITOR_OUS || '' };

  const set = new Set();
  vals.forEach(r => {
    const raw = String(r[cOU] || '').replace(/^'/, '').trim();
    if (raw && raw !== '/') {
      const parts = raw.split('/').filter(Boolean);
      let path = '';
      parts.forEach(p => { path += '/' + p; set.add(path); });
    }
  });

  return {
    ous: Array.from(set).sort(),
    current: CONFIG.MONITOR_OUS || ''
  };
}

// ===== Bulk OU Load ===========================================================

/**
 * Fetches ALL users from Admin Directory in paginated batches of 500,
 * updating OUCache and __OU_INDEX in one pass. At 4,000 users this is
 * ~8 API calls instead of up to 4,000. Only refreshes stale entries.
 */
function _bulkLoadAllOUs_(shOU) {
  const map = __getOUMap();
  const now = new Date().toISOString();
  let token;
  // Collect all stale users across all pages before touching the sheet.
  const staleUsers = []; // { email, ou }

  do {
    const params = {
      customer: 'my_customer',
      maxResults: 500,
      orderBy: 'email',
      fields: 'users(primaryEmail,orgUnitPath),nextPageToken'
    };
    if (token) params.pageToken = token;

    let resp;
    try {
      resp = AdminDirectory.Users.list(params);
    } catch (e) {
      _logDiagnostics('_bulkLoadAllOUs_/error', new Date(), new Date(), 0, 0,
        'Directory list failed: ' + (e && e.message ? e.message : String(e)));
      break;
    }

    const users = (resp && resp.users) || [];
    for (const u of users) {
      const email = String(u.primaryEmail || '').toLowerCase().trim();
      if (!email) continue;
      if (_isFreshOU_(map[email])) continue; // already fresh — skip
      staleUsers.push({ email, ou: u.orgUnitPath || '/' });
    }

    token = resp && resp.nextPageToken;
  } while (token);

  if (!staleUsers.length) return 0;

  // Update in-memory maps first (no sheet I/O yet)
  for (const { email, ou } of staleUsers) {
    map[email] = { ou, lastSeenISO: now };
    if (!__OU_INDEX) __OU_INDEX = {};
    __OU_INDEX[email] = { ou: _normalizeOU_(ou), lastSeenISO: now };
  }

  // Single batch write to sheet — one setValues call regardless of user count
  _batchWriteOURows_(shOU, staleUsers.map(({ email, ou }) => ({ email, obj: { ou, lastSeenISO: now } })));

  return staleUsers.length;
}

function bulkLoadAllOUsMenu() {
  _applyRuntimeConfig_();
  const ss = SpreadsheetApp.getActive();
  const shOU = ss.getSheetByName(CONFIG.OU_CACHE);
  if (!shOU) {
    SpreadsheetApp.getActive().toast('OUCache sheet not found. Run Install first.', 'Error', 5);
    return;
  }
  const count = _bulkLoadAllOUs_(shOU);
  SpreadsheetApp.getActive().toast(
    'Bulk OU load complete. ' + count + ' entries refreshed.',
    'Workspace Watchdog', 5
  );
}

// ===== Parallel Geo Batch =====================================================

/**
 * Geolocates an array of IPs using UrlFetchApp.fetchAll for parallelism.
 * Fires PARALLEL_GEO_BATCH IPs at once, sleeps briefly between chunks.
 * Falls back to sequential providers for any IP that fails the primary.
 * Returns: { ip: geoObject } for all successfully resolved IPs.
 */
const PARALLEL_GEO_BATCH = 10;

function _geolocateBatch_(ips) {
  const results = {};
  if (!ips || !ips.length) return results;

  const makeReq = ip => ({
    url: 'https://ipapi.co/' + encodeURIComponent(ip) + '/json/',
    muteHttpExceptions: true,
    headers: { 'Accept': 'application/json' }
  });

  for (let i = 0; i < ips.length; i += PARALLEL_GEO_BATCH) {
    const chunk = ips.slice(i, i + PARALLEL_GEO_BATCH);
    let responses;
    try {
      responses = UrlFetchApp.fetchAll(chunk.map(makeReq));
    } catch (e) {
      // fetchAll failure — fall back to sequential for this chunk
      chunk.forEach(ip => { const g = _geolocate(ip); if (g) results[ip] = g; });
      _sleep(300);
      continue;
    }

    const now = new Date().toISOString();
    responses.forEach((res, idx) => {
      const ip = chunk[idx];
      try {
        if (res.getResponseCode() !== 200) {
          const g = _geo_ipinfo(ip) || _geo_ipapicom(ip);
          if (g) results[ip] = g;
          return;
        }
        const j = JSON.parse(res.getContentText() || '{}');
        if (j.error || !_isCoord(j.latitude) || !_isCoord(j.longitude)) {
          const g = _geo_ipinfo(ip) || _geo_ipapicom(ip);
          if (g) results[ip] = g;
          return;
        }
        results[ip] = {
          city: j.city || '',
          region: j.region_code || j.region || '',
          country: j.country || '',
          isp: _cleanIsp_(j.org || j.asn || ''),
          lat: +j.latitude,
          lon: +j.longitude,
          source: 'ipapi.co',
          lastSeenISO: now
        };
      } catch (_) {
        const g = _geo_ipinfo(ip) || _geo_ipapicom(ip);
        if (g) results[ip] = g;
      }
    });

    if (i + PARALLEL_GEO_BATCH < ips.length) _sleep(250);
  }

  // Write stub entries for IPs that failed all providers
  // This prevents infinite retry on every sync for unresolvable IPs
  const now2 = new Date().toISOString();
  ips.forEach(ip => {
    if (!results[ip]) {
      results[ip] = {
        city: '', region: '', country: '', isp: '',
        lat: NaN, lon: NaN,
        source: 'failed', lastSeenISO: now2
      };
    }
  });

  return results;
}

// ===== Key Index (O(1) deduplication for large Main sheets) ==================

/**
 * KeyIndex is a hidden sheet with one Event Key per row (no header).
 * It is append-only — never rewritten — keeping it fast regardless of
 * how large Main grows. Loaded once into memory per execution.
 */
const KEY_INDEX_SHEET = 'KeyIndex';
var __KEY_INDEX = null;

function _loadKeyIndex_() {
  if (__KEY_INDEX) return __KEY_INDEX;

  const ss = SpreadsheetApp.getActive();
  let sh = ss.getSheetByName(KEY_INDEX_SHEET);
  if (!sh) {
    sh = ss.insertSheet(KEY_INDEX_SHEET);
    sh.hideSheet();
  }

  const last = sh.getLastRow();
  if (last < 1) {
    __KEY_INDEX = new Set();
    return __KEY_INDEX;
  }

  const vals = sh.getRange(1, 1, last, 1).getValues();
  __KEY_INDEX = new Set(vals.map(r => String(r[0])).filter(Boolean));
  return __KEY_INDEX;
}

function _appendToKeyIndex_(keys) {
  if (!keys || !keys.length) return;
  const ss = SpreadsheetApp.getActive();
  let sh = ss.getSheetByName(KEY_INDEX_SHEET);
  if (!sh) { sh = ss.insertSheet(KEY_INDEX_SHEET); sh.hideSheet(); }
  const rows = keys.map(k => [k]);
  sh.getRange(sh.getLastRow() + 1, 1, rows.length, 1).setValues(rows);
  if (!__KEY_INDEX) __KEY_INDEX = new Set();
  keys.forEach(k => __KEY_INDEX.add(k));
}

/**
 * Rebuilds the KeyIndex sheet from scratch by scanning Main.
 * Run once after upgrading from v1, or if KeyIndex gets out of sync.
 */
function rebuildKeyIndex() {
  _applyRuntimeConfig_();
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  if (!shMain) { SpreadsheetApp.getActive().toast('Main sheet not found.', 'Error', 5); return; }

  const keyIdx = MAIN_HEADERS.indexOf('Event Key');
  const rows = _getRows(shMain);
  const keys = rows.map(r => r[keyIdx]).filter(Boolean);

  let sh = ss.getSheetByName(KEY_INDEX_SHEET);
  if (!sh) { sh = ss.insertSheet(KEY_INDEX_SHEET); sh.hideSheet(); }
  else sh.clearContents();

  if (keys.length) sh.getRange(1, 1, keys.length, 1).setValues(keys.map(k => [k]));
  __KEY_INDEX = new Set(keys);

  SpreadsheetApp.getActive().toast(
    'KeyIndex rebuilt with ' + keys.length + ' keys.',
    'Workspace Watchdog', 5
  );
}


// ===== Batch Sheet Writers ====================================================
//
// These replace per-row setValues() loops with a single setValues() call,
// dramatically reducing Sheets API I/O when enriching many IPs or users at once.
// _upsertGeoRow_ / _upsertOURow_ are kept for single-row callers (warmup, etc.)


/**
 * Re-attempts geo lookup for IPs in GeoCache that previously failed
 * (source='failed'). Called as part of scheduledSync to gradually
 * fill in missing geo data without blocking the main sync.
 */
function _retryFailedGeoLookups_(shGeo) {
  if (!shGeo || shGeo.getLastRow() <= 1) return;
  const data = shGeo.getRange(2, 1, shGeo.getLastRow() - 1, GEO_HEADERS.length).getValues();
  const retryIPs = [];
  for (const r of data) {
    if (String(r[7] || '') === 'failed') retryIPs.push(String(r[0] || ''));
  }
  if (!retryIPs.length) return;

  // Only retry up to 5 at a time to avoid blocking sync
  const batch = retryIPs.slice(0, 5);
  let resolved = 0, stillFailed = 0;
  batch.forEach(ip => {
    if (!ip) return;
    _sleep(400);
    const g = _geolocate(ip);
    if (g && g.source !== 'failed') {
      _upsertGeoRow_(shGeo, ip, g);
      if (__GEO_INDEX) __GEO_INDEX[ip] = g;
      resolved++;
    } else {
      stillFailed++;
    }
  });
  if (batch.length) {
    _logDiagnostics('geoRetry', new Date(), new Date(), resolved, 0,
      'Geo retry: ' + resolved + ' resolved, ' + stillFailed + ' still failed of ' + batch.length + ' attempted');
  }
}

/**
 * Writes multiple geo entries to GeoCache in as few setValues() calls as possible.
 * Entries that already have a known row are grouped into contiguous range writes
 * where possible; new entries are appended in a single block.
 *
 * @param {Sheet}  shGeo      The GeoCache sheet
 * @param {Object} geoMap     { ip: geoObject } — all entries to persist
 */
function _batchWriteGeoRows_(shGeo, geoMap) {
  const entries = Object.entries(geoMap);
  if (!entries.length) return;

  if (!__GEO_ROW_INDEX) __GEO_ROW_INDEX = {};
  if (!__GEO_INDEX)     __GEO_INDEX     = {};

  const now = new Date().toISOString();
  const toUpdate = []; // { sheetRow, row[] }
  const toAppend = []; // row[]

  for (const [ip, g] of entries) {
    const row = [
      ip,
      g.city    || '',
      g.region  || '',
      g.country || '',
      g.isp     || '',
      _num(g.lat),
      _num(g.lon),
      g.source  || '',
      g.lastSeenISO || now
    ];
    // Update in-memory index
    __GEO_INDEX[ip] = {
      city: g.city||'', region: g.region||'', country: g.country||'',
      isp: g.isp||'', lat: _num(g.lat), lon: _num(g.lon),
      source: g.source||'', lastSeenISO: g.lastSeenISO||now
    };
    if (__GEO_ROW_INDEX[ip]) {
      toUpdate.push({ sheetRow: __GEO_ROW_INDEX[ip], row });
    } else {
      toAppend.push({ ip, row });
    }
  }

  // Flush updates — write each individually (rows are scattered, not contiguous)
  // Still much faster than the old full-sheet-read approach; and updates only
  // happen on TTL refresh, not on every cold install.
  for (const { sheetRow, row } of toUpdate) {
    shGeo.getRange(sheetRow, 1, 1, GEO_HEADERS.length).setValues([row]);
  }

  // Flush appends — all new rows in a single setValues block
  if (toAppend.length) {
    const firstNewRow = shGeo.getLastRow() + 1;
    shGeo.getRange(firstNewRow, 1, toAppend.length, GEO_HEADERS.length)
         .setValues(toAppend.map(e => e.row));
    toAppend.forEach((e, i) => { __GEO_ROW_INDEX[e.ip] = firstNewRow + i; });
  }
}

/**
 * Writes multiple OU entries to OUCache in as few setValues() calls as possible.
 * New entries are appended in a single block. Updates are written individually
 * (they are rare — only on TTL expiry, not cold install).
 *
 * @param {Sheet} shOU     The OUCache sheet
 * @param {Array} entries  [{ email, obj: { ou, lastSeenISO } }, ...]
 */
function _batchWriteOURows_(shOU, entries) {
  if (!entries || !entries.length) return;

  if (!__OU_ROW_INDEX) __OU_ROW_INDEX = {};
  if (!__OU_INDEX)     __OU_INDEX     = {};

  const now = new Date().toISOString();
  const toUpdate = []; // { sheetRow, row[] }
  const toAppend = []; // { key, row[] }

  for (const { email, obj } of entries) {
    const key = String(email || '').toLowerCase().trim();
    if (!key) continue;
    const row = [
      email,
      _asTextLiteral_(_resolveOU_(email, obj.ou || '')),
      obj.lastSeenISO || now
    ];
    // Update in-memory index
    __OU_INDEX[key] = {
      ou: _normalizeOU_(obj.ou || ''),
      lastSeenISO: obj.lastSeenISO || now
    };
    if (__OU_ROW_INDEX[key]) {
      toUpdate.push({ sheetRow: __OU_ROW_INDEX[key], row });
    } else {
      toAppend.push({ key, row });
    }
  }

  // Flush updates individually (rare — TTL-expiry refreshes only)
  for (const { sheetRow, row } of toUpdate) {
    shOU.getRange(sheetRow, 1, 1, OU_HEADERS.length).setValues([row]);
  }

  // Flush appends — all new users in a single setValues block
  if (toAppend.length) {
    const firstNewRow = shOU.getLastRow() + 1;
    shOU.getRange(firstNewRow, 1, toAppend.length, OU_HEADERS.length)
        .setValues(toAppend.map(e => e.row));
    toAppend.forEach((e, i) => { __OU_ROW_INDEX[e.key] = firstNewRow + i; });
  }
}

// ===== GEO (cache) ===========================================================

function _geolocate(ip) {
  if (!ip) return null;
  const r1 = _geo_ipapi(ip);       if (r1) return r1;
  const r2 = _geo_ipinfo(ip);      if (r2) return r2;
  const r3 = _geo_ipapicom(ip);    if (r3) return r3;
  return null;
}
function _geo_ipapi(ip) {
  try {
    const u = 'https://ipapi.co/' + encodeURIComponent(ip) + '/json/';
    const res = UrlFetchApp.fetch(u, {muteHttpExceptions:true, timeout:10000});
    if (res.getResponseCode() !== 200) return null;
    const j = JSON.parse(res.getContentText()||'{}');
    if (j.error) return null;
    if (!_isCoord(j.latitude) || !_isCoord(j.longitude)) return null;
    return {city:j.city||'', region:j.region_code||j.region||'', country:j.country||'', isp:_cleanIsp_(j.org||j.asn||''), lat:+j.latitude, lon:+j.longitude, source:'ipapi.co', lastSeenISO:new Date().toISOString()};
  } catch (_) { return null; }
}
function _geo_ipinfo(ip) {
  try {
    const tok = PropertiesService.getScriptProperties().getProperty('IPINFO_TOKEN');
    const u = 'https://ipinfo.io/' + encodeURIComponent(ip) + '/json' + (tok ? ('?token=' + encodeURIComponent(tok)) : '');
    const res = UrlFetchApp.fetch(u, {muteHttpExceptions:true, timeout:10000});
    if (res.getResponseCode() !== 200) return null;
    const j = JSON.parse(res.getContentText()||'{}');
    if (!j.loc) return null;
    const parts = String(j.loc).split(',');
    const lat = Number(parts[0]), lon = Number(parts[1]);
    if (!_isCoord(lat) || !_isCoord(lon)) return null;
    return {city:j.city||'', region:j.region||'', country:j.country||'', isp:_cleanIsp_(j.org||j.hostname||''), lat:lat, lon:lon, source:'ipinfo.io', lastSeenISO:new Date().toISOString()};
  } catch (_) { return null; }
}
function _geo_ipapicom(ip) {
  try {
    const u = 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as';
    const res = UrlFetchApp.fetch(u, {muteHttpExceptions:true, timeout:10000});
    if (res.getResponseCode() !== 200) return null;
    const j = JSON.parse(res.getContentText()||'{}');
    if (j.status !== 'success') return null;
    return {city:j.city||'', region:j.region||j.regionName||'', country:j.countryCode||j.country||'', isp:_cleanIsp_(j.isp||j.org||j.as||''), lat:+j.lat, lon:+j.lon, source:'ip-api.com', lastSeenISO:new Date().toISOString()};
  } catch (_) { return null; }
}
function _loadGeoMap_(shGeo) {
  if (__GEO_INDEX) return __GEO_INDEX;

  const map = {};
  const rowIdx = {};
  const vals = _getRows(shGeo);
  vals.forEach((r, i) => {
    const ip = r[0];
    if (!ip) return;
    map[ip] = {
      city: r[1],
      region: r[2],
      country: r[3],
      isp: r[4] || '',
      lat: _num(r[5]),
      lon: _num(r[6]),
      source: r[7],
      lastSeenISO: r[8]
    };
    rowIdx[ip] = i + 2; // +2: 1-based index + skip header row
  });

  __GEO_INDEX = map;
  __GEO_ROW_INDEX = rowIdx;
  return map;
}
function _isFreshGeo_(g) {
  if (!g || !g.lastSeenISO) return false;
  const ageH = (Date.now() - new Date(g.lastSeenISO).getTime())/3600000;
  return ageH < CONFIG.GEO_TTL_HOURS;
}
function _upsertGeoRow_(shGeo, ip, g) {
  // Use in-memory row index to avoid a full sheet re-read on every write.
  if (!__GEO_ROW_INDEX) __GEO_ROW_INDEX = {};
  const existingRow = __GEO_ROW_INDEX[ip]; // 1-based sheet row, or undefined
  const now = new Date().toISOString();
  const row = [ip, g.city||'', g.region||'', g.country||'', g.isp||'', _num(g.lat), _num(g.lon), g.source||'', g.lastSeenISO||now];

  if (existingRow) {
    shGeo.getRange(existingRow, 1, 1, GEO_HEADERS.length).setValues([row]);
  } else {
    const newRow = shGeo.getLastRow() + 1;
    shGeo.getRange(newRow, 1, 1, GEO_HEADERS.length).setValues([row]);
    __GEO_ROW_INDEX[ip] = newRow;
  }

  if (!__GEO_INDEX) __GEO_INDEX = {};
  __GEO_INDEX[ip] = {
    city: g.city||'',
    region: g.region||'',
    country: g.country||'',
    isp: g.isp||'',
    lat: _num(g.lat),
    lon: _num(g.lon),
    source: g.source||'',
    lastSeenISO: g.lastSeenISO||now
  };
}

// ===== OU (cache) ============================================================

function _getOUForEmail_(email) {
  try {
    if (!email) return '';
    var u = AdminDirectory.Users.get(email);
    return (u && u.orgUnitPath) ? String(u.orgUnitPath) : '';
  } catch (e) {
    return '';
  }
}
// _loadOUMap_() — canonical no-param version is defined below near __OU_MAP_CACHE.
// This named alias exists so callers that pass shOU still compile; the arg is ignored
// since the singleton __OU_INDEX is always used.
function _loadOUMap_(shOU) { // eslint-disable-line no-unused-vars
  return __getOUMap();
}
function _isFreshOU_(o) {
  if (!o || !o.lastSeenISO) return false;
  const ageH = (Date.now() - new Date(o.lastSeenISO).getTime())/3600000;
  return ageH < CONFIG.OU_TTL_HOURS;
}
function _upsertOURow_(shOU, email, obj) {
  // Use in-memory row index to avoid a full sheet re-read on every write.
  if (!__OU_ROW_INDEX) __OU_ROW_INDEX = {};
  const key = String(email || '').toLowerCase();
  const existingRow = __OU_ROW_INDEX[key]; // 1-based sheet row, or undefined
  const now = new Date().toISOString();
  const row = [email, _asTextLiteral_(_resolveOU_(email, obj.ou || '')), obj.lastSeenISO || now];

  if (existingRow) {
    shOU.getRange(existingRow, 1, 1, OU_HEADERS.length).setValues([row]);
  } else {
    const newRow = shOU.getLastRow() + 1;
    shOU.getRange(newRow, 1, 1, OU_HEADERS.length).setValues([row]);
    __OU_ROW_INDEX[key] = newRow;
  }

  if (!__OU_INDEX) __OU_INDEX = {};
  __OU_INDEX[key] = {
    ou: _normalizeOU_(obj.ou || ''),
    lastSeenISO: obj.lastSeenISO || now
  };
}

// ===== Backfill (used inside Active Now fallback) ============================

function _backfillGeoForEmail_(email, shGeo, geoMap, lookbackDays) {
  const ev = _fetchLatestLoginEventForUser_(email, lookbackDays || 180);
  if (!ev || !ev.ip) return null;
  let g = geoMap[ev.ip];
  if (!g || !_isFreshGeo_(g)) {
    g = _geolocate(ev.ip);
    if (g) { geoMap[ev.ip] = g; _upsertGeoRow_(shGeo, ev.ip, g); }
  }
  if (!g) return { ip: ev.ip };
  return { ip: ev.ip, city: g.city||'', region: g.region||'', country: g.country||'', isp: g.isp||'',
           lat: _num(g.lat), lon: _num(g.lon), source: g.source||'' };
}

function _fetchLatestLoginEventForUser_(email, lookbackDays) {
  try {
    if (!email) return null;
    const endU = new Date();
    const startU = new Date(endU.getTime() - (lookbackDays || 180) * 24 * 3600000);
    const params = { startTime: startU.toISOString(), endTime: endU.toISOString(), maxResults: 500 };
    let page, latest = null;
    do {
      if (page) params.pageToken = page;
      const resp = AdminReports.Activities.list(email, 'login', params);
      const items = (resp && resp.items) || [];
      for (var i=0;i<items.length;i++) {
        var a = items[i];
        var ts = new Date(a.id.time);
        var ip = a.ipAddress || '';
        if (!ip) continue;
        if (!latest || ts > latest.ts) latest = { ts: ts, ip: ip };
      }
      page = resp && resp.nextPageToken;
    } while (page);
    return latest;
  } catch (_) { return null; }
}

/**
 * Backfill helpers — chunked, enriched, safe.
 * Does NOT touch lastRunISO, so your normal scheduled sync window is preserved.
 */

// Pull exactly 4 days in 6-hour chunks (safe default)

/**
 * Scans the Main sheet for rows with blank geo data and fills them in
 * from GeoCache. Run this after GeoCache has been populated.
 */
function fillBlankGeoInMain() {
  _applyRuntimeConfig_();
  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shGeo  = ss.getSheetByName(CONFIG.GEOCACHE);
  if (!shMain || shMain.getLastRow() <= 1) {
    SpreadsheetApp.getActive().toast('Main sheet is empty.', 'Workspace Watchdog', 3);
    return;
  }

  // Build geo map from GeoCache
  const geoMap = _loadGeoMap_(shGeo);

  // Read all Main rows
  const lastRow = shMain.getLastRow();
  const data    = shMain.getRange(2, 1, lastRow - 1, MAIN_HEADERS.length).getValues();

  // Col indices (0-based)
  const COL_IP      = 3;   // D
  const COL_CITY    = 4;   // E
  const COL_REGION  = 5;   // F
  const COL_COUNTRY = 6;   // G
  const COL_ISP     = 7;   // H
  const COL_LATLNG  = 10;  // K
  const COL_GEOSRC  = 11;  // L
  const COL_OUTSIDE = 15;  // P
  const COL_HASGEO  = 16;  // Q

  let updated = 0;
  const updates = []; // { rowIndex, values }

  data.forEach((r, i) => {
    const ip  = String(r[COL_IP] || '').trim();
    const city = String(r[COL_CITY] || '').trim();
    if (!ip || city) return; // skip if no IP or already has geo

    const g = geoMap[ip];
    if (!g || g.source === 'failed' || !g.city) return;

    const latlng   = (isFinite(g.lat) && isFinite(g.lon)) ? g.lat + ',' + g.lon : '';
    const outsideUS = g.country && g.country !== 'US';

    updates.push({
      row: i + 2, // 1-based sheet row
      city:    g.city    || '',
      region:  g.region  || '',
      country: g.country || '',
      isp:     g.isp     || '',
      latlng,
      geosrc:  g.source  || '',
      outsideUS,
      hasGeo:  !!latlng
    });
  });

  if (!updates.length) {
    SpreadsheetApp.getActive().toast('No blank geo rows found in Main sheet.', 'Workspace Watchdog', 4);
    return;
  }

  // Write updates one row at a time (could batch but keep simple for safety)
  updates.forEach(u => {
    shMain.getRange(u.row, COL_CITY    + 1).setValue(u.city);
    shMain.getRange(u.row, COL_REGION  + 1).setValue(u.region);
    shMain.getRange(u.row, COL_COUNTRY + 1).setValue(u.country);
    shMain.getRange(u.row, COL_ISP     + 1).setValue(u.isp);
    shMain.getRange(u.row, COL_LATLNG  + 1).setValue(u.latlng);
    shMain.getRange(u.row, COL_GEOSRC  + 1).setValue(u.geosrc);
    shMain.getRange(u.row, COL_OUTSIDE + 1).setValue(u.outsideUS);
    shMain.getRange(u.row, COL_HASGEO  + 1).setValue(u.hasGeo);
    updated++;
  });

  SpreadsheetApp.getActive().toast(
    'Filled geo data for ' + updated + ' row(s) in Main sheet.',
    'Workspace Watchdog', 5);
}

function backfillFourDays() {
  backfillDays(4, 6);
}


function _sleep(ms) { Utilities.sleep(ms || 200); }

// Generic retry w/ exponential backoff for flaky Admin Reports calls
function _withRetries_(label, maxAttempts, fn) {
  maxAttempts = Math.max(1, Number(maxAttempts) || 4);
  var attempt = 0, lastErr;
  while (attempt < maxAttempts) {
    try {
      return fn();
    } catch (e) {
      lastErr = e;
      var msg = (e && e.message) ? e.message : String(e);
      // Retry for transient / empty-body weirdness / 5xx
      var retryable = /Empty response|Internal error|Backend Error|Service unavailable|429|5\d\d/i.test(msg);
      if (!retryable) throw e;
      var delay = Math.min(8000, Math.pow(2, attempt) * 500); // 0.5s,1s,2s,4s,8s
      _sleep(delay);
      attempt++;
    }
  }
  throw lastErr;
}

// Safe wrapper for AdminReports.Activities.list
function _reportsListSafe_(userKey, appName, params) {
  return _withRetries_('reports.list ' + appName, 5, function() {
    var resp = AdminReports.Activities.list(userKey, appName, params);
    // Some failure modes return null/undefined instead of throwing
    if (!resp || typeof resp !== 'object') throw new Error('Empty response');
    return resp;
  });
}





/**
 * Backfill N days, in chunkHours slices (e.g., 6h) with Geo+OU enrichment.
 * @param {number} days        Number of days to backfill (default 4)
 * @param {number} chunkHours  Chunk size in hours (default 6)
 */
function backfillDays(days, chunkHours) {
  const __ouMap = __getOUMap();
  days = Number(days) || 4;
  chunkHours = Number(chunkHours) || 6;

  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shGeo  = ss.getSheetByName(CONFIG.GEOCACHE);
  const shOU   = ss.getSheetByName(CONFIG.OU_CACHE);

  const endAll = new Date();                         // now
  const startAll = new Date(endAll.getTime() - days*24*3600000);

  // Warm caches once; we’ll keep them updated as we go
  const geoMap = _loadGeoMap_(shGeo);
  const ouMap  = _loadOUMap_(shOU);

  let cursor = new Date(startAll);
  let totalParsed = 0, totalAppended = 0, batches = 0;

  while (cursor < endAll) {
    const sliceStart = new Date(cursor);
    const sliceEnd   = new Date(Math.min(cursor.getTime() + chunkHours*3600000, endAll.getTime()));

    // Fetch (raw rows) for this slice
    const {rows, count, uniqueIps, uniqueEmails} = _fetchLoginRows_(sliceStart, sliceEnd, 'backfillDays');
    totalParsed += count;

    // Enrich caches opportunistically (only for missing/stale)
    const ipsToEnrich = [];
    uniqueIps.forEach(ip => { if (ip && !_isFreshGeo_(geoMap[ip])) ipsToEnrich.push(ip); });
    if (ipsToEnrich.length) {
      const batchResults = _geolocateBatch_(ipsToEnrich);
      Object.entries(batchResults).forEach(([ip, g]) => { geoMap[ip] = g; });
      _batchWriteGeoRows_(shGeo, batchResults);
    }

    // OU: bulk load covers everything for BULK_OU_LOAD mode; per-email fallback otherwise
    if (!CONFIG.BULK_OU_LOAD) {
      const emailsToFetch = [];
      uniqueEmails.forEach(email => { if (email && !_isFreshOU_(__ouMap[email])) emailsToFetch.push(email); });
      const ouFetched = [];
      emailsToFetch.forEach(email => {
        const ou = _getOUForEmail_(email);
        if (ou) {
          const obj = { ou, lastSeenISO: new Date().toISOString() };
          __ouMap[email] = obj;
          if (!__OU_INDEX) __OU_INDEX = {};
          __OU_INDEX[String(email).toLowerCase()] = { ou: _normalizeOU_(ou), lastSeenISO: obj.lastSeenISO };
          ouFetched.push({ email, obj });
        }
      });
      if (ouFetched.length) _batchWriteOURows_(shOU, ouFetched);
    }

    // Map to Main schema (including the precomputed tail)
    if (rows.length) {
      const out = rows.map(r => {
        const g  = geoMap[r.ip] || {};
        const ou = (__ouMap[r.email] && __ouMap[r.email].ou) || '';

        const parsedNoTZ = _fmtCT_no_tz_(r.ts);
        const hourBucket = _hourBucketNoTZ_(r.ts);
        const outsideUS  = (g.country && String(g.country).toUpperCase() !== 'US') ? true : false;
        const hasGeo     = (_isCoord(g.lat) && _isCoord(g.lon)) ? 'Yes' : 'No';
        const topOU      = _topOU_(ou);

        return [
          _fmtCT(r.ts), r.email, r.eventName, r.ip,
          g.city||'', g.region||'', g.country||'', g.isp||'',
          r.rawJSON, r.key,
          _fmtLatLng_(g.lat, g.lon), g.source||'',
          ou,
          // precomputed for Looker Studio (no formulas needed)
          parsedNoTZ, hourBucket, outsideUS, hasGeo, topOU
        ];
      });

      shMain.getRange(shMain.getLastRow()+1, 1, out.length, MAIN_HEADERS.length).setValues(out);
      totalAppended += out.length;
      batches++;
    }

    // Advance + be polite to quotas
    cursor = sliceEnd;
    Utilities.sleep(200);
  }

  // Housekeeping
  _dedupeSheetByKey(shMain, MAIN_HEADERS, MAIN_HEADERS.indexOf('Event Key'));
  // Rebuild derived tabs so your dashboard lights up
  _refreshActiveNow_();
  _refreshSuspicious_('backfillDays');
  // Enforce rolling retention (archive only what aged out)
  trimMainRolling();

  _logDiagnostics('backfillDays', startAll, endAll, totalParsed, totalAppended,
    'days=' + days + ', chunkHours=' + chunkHours + ', batches=' + batches);
}





// ===== Diagnostics ===========================================================


function _logDiagnostics(triggerName, startD, endD, parsed, appended, notes, extra) {
  const sh = SpreadsheetApp.getActive().getSheetByName(CONFIG.DIAG);
  const base = [triggerName, _fmtCT(startD), _fmtCT(endD), parsed||0, appended||0, notes||''];
  const x = extra || {};
  const tail = [
    Number(x.lagMin ?? ''), Number(x.overlapMin ?? ''), Number(x.newRows ?? ''), Number(x.dupesInWindow ?? ''),
    Number(x.mainBefore ?? ''), Number(x.mainAfter ?? ''), Number(x.dedupeRemoved ?? ''),
    Number(x.trimArchived ?? ''), Number(x.trimKept ?? ''),
    String(x.windowStartISO ?? ''), String(x.windowEndISO ?? '')
  ];
  sh.getRange(sh.getLastRow()+1,1,1,DIAG_HEADERS.length).setValues([ base.concat(tail) ]);
}




// ===== OU Helpers & Text Safety ==============================================

// Hard overrides for known special accounts (emails must be lowercase)
const OU_OVERRIDES = {
  'help.desk@dawsonesc.com': '/NonUserAccounts',
  // add more here if needed
};

// Convert any OU-ish value into a canonical path.
// Treat blanks, date objects, and date-looking strings as root "/" by default.
function _normalizeOU_(v) {
  if (v === null || v === undefined) return '/';
  if (Object.prototype.toString.call(v) === '[object Date]') return '/';
  const s = String(v).trim();
  if (s === '' || s === '/') return '/';
  if (/^\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}$/.test(s)) return '/';
  return s.startsWith('/') ? s : '/' + s;
}

// If there's an explicit override for this email, use it; otherwise normalize
function _resolveOU_(email, ou) {
  const e = String(email || '').toLowerCase().trim();
  if (OU_OVERRIDES && OU_OVERRIDES[e]) return OU_OVERRIDES[e];
  return _normalizeOU_(ou);
}

// Force a value to TEXT in Sheets. Date objects become yyyy-mm-dd first.
function _asTextLiteral_(v) {
  if (v === null || v === undefined) return '';
  if (Object.prototype.toString.call(v) === '[object Date]') {
    const d = v, y = d.getFullYear(), m = d.getMonth()+1, dd = d.getDate();
    v = y + '-' + (m<10?'0':'') + m + '-' + (dd<10?'0':'') + dd;
  }
  const s = String(v);
  return s === '' ? '' : "'" + s;
}

// Load OU cache into a map: { emailLower: { ou: '/path', lastSeenISO: '...' } }
// Also populates __OU_ROW_INDEX for O(1) upsert row targeting.
function _loadOUMap_() {
  if (__OU_INDEX) return __OU_INDEX;

  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.OU_CACHE);
  if (!sh) return {};
  const last = sh.getLastRow(); if (last <= 1) return {};

  const header = sh.getRange(1,1,1, sh.getLastColumn()).getValues()[0];
  const cEmail = header.indexOf('Email') + 1;
  const cOU    = header.indexOf('OrgUnitPath') + 1;
  const cSeen  = header.indexOf('LastSeenISO') + 1;
  if (cEmail <= 0 || cOU <= 0) return {};

  const vals = sh.getRange(2, 1, last-1, sh.getLastColumn()).getValues();
  const map = {};
  const rowIdx = {};
  for (let i = 0; i < vals.length; i++) {
    const row = vals[i];
    const email = String(row[cEmail-1] || '').toLowerCase().trim();
    if (!email) continue;
    map[email] = {
      ou: _normalizeOU_(row[cOU-1]),
      lastSeenISO: cSeen > 0 ? (row[cSeen-1] || '') : ''
    };
    rowIdx[email] = i + 2; // +2: 1-based + skip header row
  }

  __OU_INDEX = map;
  __OU_ROW_INDEX = rowIdx;
  return map;
}



// ===== OU Map Singleton (prevents re-declare) =================================
var __OU_MAP_CACHE = null;
function __getOUMap() {
  if (!__OU_MAP_CACHE) __OU_MAP_CACHE = _loadOUMap_();
  return __OU_MAP_CACHE;
}

// Resets all in-memory caches (call at the top of _syncCore and after install).
function _resetAllCaches_() {
  __GEO_INDEX     = null;
  __OU_INDEX      = null;
  __GEO_ROW_INDEX = null;
  __OU_ROW_INDEX  = null;
  __OU_MAP_CACHE  = null;
  __KEY_INDEX     = null;
  __WHITELIST      = null;
}


// ===== Utilities =============================================================

function _ensureAllSheets() {
  const ss = SpreadsheetApp.getActive();
  [CONFIG.MAIN, CONFIG.GEOCACHE, CONFIG.OU_CACHE, CONFIG.ACTIVE, CONFIG.SUSPICIOUS, CONFIG.DIAG, CONFIG.ARCHIVE, 'Setup']
    .forEach(n => { if (!ss.getSheetByName(n)) ss.insertSheet(n); });
  // KeyIndex is a hidden performance sheet — create and hide if missing
  if (!ss.getSheetByName(KEY_INDEX_SHEET)) {
    const ki = ss.insertSheet(KEY_INDEX_SHEET);
    ki.hideSheet();
  }
}

// Non-destructive header setter: appends new tail columns, avoids wiping data
function _ensureHeaders(sh, headers) {
  const lastCol = sh.getLastColumn();
  const have = lastCol ? sh.getRange(1,1,1,lastCol).getValues()[0] : [];
  const minLen = Math.min(have.length, headers.length);
  const prefixMatch = have.slice(0, minLen).join('') === headers.slice(0, minLen).join('');
  if (prefixMatch && headers.length > have.length) {
    sh.getRange(1, have.length+1, 1, headers.length - have.length).setValues([headers.slice(have.length)]);
    return;
  }
  if (have.join('') !== headers.join('')) _setHeaders(sh, headers);
}

function _setHeaders(sh, headers) {
  _clearBody(sh);
  sh.getRange(1,1,1,headers.length).setValues([headers]);
}

function _clearBody(sh) {
  const last = sh.getLastRow();
  if (last > 1) sh.getRange(2,1,last-1, sh.getLastColumn()).clearContent();
}

function _dedupeSheetByKey(sh, headers, keyIdx) {
  const data = _getRows(sh);
  if (data.length === 0) { _setHeaders(sh, headers); return; }
  const map = new Map();
  const tsIdx = headers.indexOf('Timestamp');
  data.forEach(r => {
    const k = r[keyIdx]; if (!k) return;
    if (!map.has(k)) map.set(k, r);
    else {
      const a = map.get(k);
      const ta = tsIdx >= 0 ? new Date(a[tsIdx]).getTime() : 0;
      const tb = tsIdx >= 0 ? new Date(r[tsIdx]).getTime() : 1;
      if (tb >= ta) map.set(k, r);
    }
  });
  const out = Array.from(map.values());
  _clearBody(sh);
  _setHeaders(sh, headers);
  if (out.length) sh.getRange(2,1,out.length,headers.length).setValues(out);
}

function _dedupeByComposite_(sh, idxes, headers) {
  const vals = _getRows(sh);
  const seen = new Set();
  const out = [];
  for (const r of vals) {
    const key = idxes.map(i => r[i] ?? '').join('|');
    if (!seen.has(key)) { seen.add(key); out.push(r); }
  }
  _clearBody(sh);
  const hdrs = headers || SUSP_HEADERS;
  sh.getRange(1,1,1,hdrs.length).setValues([hdrs]);
  if (out.length) sh.getRange(2,1,out.length,hdrs.length).setValues(out);
}

function _getRows(sh) {
  const last = sh.getLastRow();
  if (last <= 1) return [];
  return sh.getRange(2,1,last-1, sh.getLastColumn()).getValues();
}

function _mkKey_(s) { return Utilities.base64EncodeWebSafe(s).slice(0, 44); }
// Combines lat and lon into a single "lat,lon" string for Looker Studio geo fields.
// Returns '' if either coordinate is missing or invalid.
function _fmtLatLng_(lat, lon) {
  const la = _num(lat), lo = _num(lon);
  if (la === '' || lo === '') return '';
  return la + ',' + lo;
}
// Strips the leading ASN prefix (e.g. "AS33294 ") from ISP strings returned
// by geo providers, leaving just the human-readable organisation name.
function _cleanIsp_(raw) {
  return String(raw || '').replace(/^AS\d+\s+/, '').trim();
}
function _num(x) { const n = Number(x); return isFinite(n) ? n : ''; }
function _isCoord(x) { return typeof x === 'number' && isFinite(x); }
function _fmtCT(d) { return Utilities.formatDate(d, CONFIG.TZ, "yyyy-MM-dd'T'HH:mm:ssXXX"); }
function _fmtCT_no_tz_(d) { return Utilities.formatDate(d, CONFIG.TZ, "yyyy-MM-dd HH:mm:ss"); }
function _hourBucketNoTZ_(d) { const h = new Date(d); h.setMinutes(0,0,0); return _fmtCT_no_tz_(h); }
function _haversineMi(lat1,lon1,lat2,lon2) {
  const toRad = deg => deg * Math.PI / 180;
  const R = 3958.7613;
  const dLat = toRad(lat2-lat1), dLon = toRad(lon2-lon1);
  const a = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)*Math.sin(dLon/2);
  return R * 2 * Math.asin(Math.sqrt(a));
}
function _topOU_(path) {
  if (!path) return "(none)";
  var s = String(path);
  if (s === "/") return "(none)";
  var parts = s.split("/");
  return parts.length > 1 && parts[1] ? parts[1] : "(none)";
}

// Tolerant trigger cleanup
function _deleteMyTriggers_() {
  try {
    const me = ScriptApp.getProjectTriggers();
    me.forEach(function(t) {
      if (['scheduledSync','weeklyReset','cacheWarmup','dailyDigest'].includes(t.getHandlerFunction())) {
        ScriptApp.deleteTrigger(t);
      }
    });
  } catch (e) {
    _logDiagnostics('install/_deleteMyTriggers_', new Date(), new Date(), 0, 0,
      'Skip trigger cleanup: ' + (e && e.message ? e.message : e));
  }
}



function fixActiveNow_OU_FromCache() {
  const ss = SpreadsheetApp.getActive();
  const shA = ss.getSheetByName(CONFIG.ACTIVE);
  if (!shA) return;
  const last = shA.getLastRow(); if (last <= 1) return;

  const hdr = shA.getRange(1,1,1, shA.getLastColumn()).getValues()[0];
  const cEmail = hdr.indexOf('Email') + 1;
  const cOU    = hdr.indexOf('OU') + 1;
  if (cEmail <= 0 || cOU <= 0) return;

  const emails = shA.getRange(2, cEmail, last-1, 1).getValues().map(r => String(r[0]||'').toLowerCase());
  const __ouMap = __getOUMap();
  const out = emails.map(e => [ _asTextLiteral_(_resolveOU_(e, (__ouMap[e]?.ou ?? ''))) ]);

  const rng = shA.getRange(2, cOU, last-1, 1);
  rng.setNumberFormat('@');
  rng.setValues(out);
}

/**
 * === Archive Pruning (additive; safe to paste anywhere) ======================
 * Keeps Archive from becoming a molasses swamp.
 *
 * You can run:
 *   pruneArchiveByDays();            // default keep 90 days
 *   pruneArchiveByMaxRows();         // default keep last 20,000 rows
 *   pruneArchiveSmart();             // enforce BOTH: keep 90 days AND cap 20,000
 *   addArchivePruneTrigger();        // adds a nightly trigger at 1am CT
 *
 * None of these modify CONFIG. They rely on your existing helpers.
 */

// Keep only rows in Archive whose Timestamp (col A) is within last N days.
function pruneArchiveByDays(keepDays) {
  _pruneArchive_({ keepDays: Number(keepDays) || 90, maxRows: null });
}

// Keep only the last N rows in Archive (newest first after sort by Timestamp).
function pruneArchiveByMaxRows(maxRows) {
  _pruneArchive_({ keepDays: null, maxRows: Number(maxRows) || 20000 });
}

// Do both: trim to last keepDays and then enforce maxRows cap.
function pruneArchiveSmart(keepDays, maxRows) {
  _pruneArchive_({
    keepDays: (keepDays === undefined ? 90 : Number(keepDays) || 90),
    maxRows:  (maxRows  === undefined ? 20000 : Number(maxRows) || 20000)
  });
}

// Adds a nightly time-based trigger (1am America/Chicago) for pruneArchiveSmart.
function addArchivePruneTrigger() {
  // Avoid piling up duplicates if you run this twice.
  try {
    ScriptApp.getProjectTriggers().forEach(t => {
      if (t.getHandlerFunction && t.getHandlerFunction() === 'pruneArchiveSmart') {
        ScriptApp.deleteTrigger(t);
      }
    });
  } catch (e) {} // best-effort cleanup

  ScriptApp.newTrigger('pruneArchiveSmart').timeBased().atHour(1).everyDays(1).create();
}

/** Internal: does the pruning work (age + size) with defensive guards. */
function _pruneArchive_(opts) {
  const t0 = new Date();
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.ARCHIVE);
  if (!sh) return;

  const header = sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0] || [];
  if (!header.length) return;

  const rows = _getRows(sh); // body-only
  if (!rows.length) return;

  // Build objects with parsed timestamps to sort/filter safely.
  const items = rows.map(r => {
    const ts = new Date(r[0]); // Timestamp in col A (CT ISO)
    return { ts: isNaN(ts) ? null : ts, row: r };
  });

  // Sort newest → oldest by timestamp where possible, but keep nulls last
  items.sort((a,b) => {
    if (!a.ts && !b.ts) return 0;
    if (!a.ts) return 1;
    if (!b.ts) return -1;
    return b.ts - a.ts;
  });

  let kept = items;

  // Age filter
  if (opts.keepDays && opts.keepDays > 0) {
    const cutoff = new Date(Date.now() - opts.keepDays * 24 * 3600000);
    kept = kept.filter(x => !x.ts || x.ts >= cutoff); // keep rows with invalid dates too (defensive)
  }

  // Size cap
  if (opts.maxRows && opts.maxRows > 0 && kept.length > opts.maxRows) {
    kept = kept.slice(0, opts.maxRows); // we already sorted newest→oldest
  }

  // If nothing changed, bail quickly.
  if (kept.length === rows.length) {
    _logDiagnostics('_pruneArchive_/noop', t0, new Date(), 0, kept.length,
      'No change. Rows=' + kept.length);
    return;
  }

  // Rebuild sheet body (fastest path vs many deleteRows).
  _clearBody(sh);
  if (kept.length) sh.getRange(2,1,kept.length, sh.getLastColumn()).setValues(kept.map(x => x.row));

  // Optional: de-dupe by Event Key in case upstream appended overlaps.
  const keyIdx = header.indexOf('Event Key');
  if (keyIdx >= 0) _dedupeSheetByKey(sh, header, keyIdx);

  _logDiagnostics('_pruneArchive_', t0, new Date(), 0, kept.length,
    'Pruned to rows=' + kept.length +
    (opts.keepDays ? (', keepDays=' + opts.keepDays) : '') +
    (opts.maxRows ? (', maxRows=' + opts.maxRows) : ''));
}


// === ActiveNow menu wrappers ===================================================
function rebuildActiveNow() { _refreshActiveNow_(Number(CONFIG.ACTIVE_WINDOW_MINUTES || 30)); }
function rebuildActiveNow30() { _refreshActiveNow_(30); }
function rebuildActiveNow60() { _refreshActiveNow_(60); }


function cacheWarmup() {
  _applyRuntimeConfig_();

  const ss = SpreadsheetApp.getActive();
  const main = ss.getSheetByName(CONFIG.MAIN);
  const geo = ss.getSheetByName(CONFIG.GEOCACHE);
  const ou = ss.getSheetByName(CONFIG.OU_CACHE);

  if (!main || !geo || !ou) return;

  const rows = main.getDataRange().getValues();
  if (!rows || rows.length < 2) return;

  const headers = rows.shift();
  const ipIndex = headers.indexOf('IP');
  const emailIndex = headers.indexOf('Actor Email');

  if (ipIndex === -1 || emailIndex === -1) return;

  const geoIPs = new Set(
    geo.getRange(2,1,Math.max(geo.getLastRow()-1,0),1).getValues().flat().filter(Boolean)
  );

  const ouUsers = new Set(
    ou.getRange(2,1,Math.max(ou.getLastRow()-1,0),1).getValues().flat().filter(Boolean)
  );

  let ipCount = 0;
  let userCount = 0;

  for (const r of rows) {
    const ip = r[ipIndex];
    const email = r[emailIndex];

    if (ip && !geoIPs.has(ip) && ipCount < CONFIG.CACHE_WARMUP_BATCH_IP) {
      const g = _geolocate(ip);
      if (g) {
        geoIPs.add(ip);
        _upsertGeoRow_(geo, ip, g);
      }
      ipCount++;
    }

    if (email && !ouUsers.has(email) && userCount < CONFIG.CACHE_WARMUP_BATCH_USER) {
      const ouPath = _getOUForEmail_(email);
      if (ouPath) {
        const obj = {ou:ouPath,lastSeenISO:new Date().toISOString()};
        _upsertOURow_(ou,email,obj);
      }
      userCount++;
    }

    if (ipCount >= CONFIG.CACHE_WARMUP_BATCH_IP &&
        userCount >= CONFIG.CACHE_WARMUP_BATCH_USER) break;
  }
}



// ===== Live Map Data Functions ================================================
// Called from LiveMap.html via google.script.run

/**
 * Returns Main sheet rows as lightweight objects for the live map.
 * Applies a maxRows cap to keep payload size manageable.
 * Filters are applied server-side to reduce data transfer.
 */

// ===== User Risk Scoring =====================================================
//
// Calculates a 0-100 risk score per user from the last 7 days of data.
// Scores are computed on demand and not stored in the sheet.
//
// Weights:
//   +5  per failed login
//   +10 per outside-US login
//   +20 per impossible travel flag (Suspicious sheet)
//   +15 per login burst flag (Suspicious sheet)
//   +3  per login between midnight and 5am CT

function getUserRiskScores() {
  _applyRuntimeConfig_();
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const scores  = {};
  const cutoff  = new Date(Date.now() - 7 * 24 * 3600000);

  // Helper to ensure entry exists
  function ensure(email) {
    if (!scores[email]) scores[email] = 0;
  }

  // ── Score from Main sheet ──────────────────────────────────────────────────
  if (shMain && shMain.getLastRow() > 1) {
    const rows = shMain.getRange(2, 1, shMain.getLastRow() - 1, 16).getValues();
    for (const r of rows) {
      const ts     = r[0];
      const email  = String(r[1] || '').toLowerCase();
      const evName = String(r[2] || '');
      const outside= r[15];
      if (!email || new Date(ts) < cutoff) continue;
      ensure(email);

      if (evName === 'login_failure') scores[email] += 5;
      if (outside === true)           scores[email] += 10;

      // Unusual hour (midnight to 5am CT)
      const hourCT = Number(Utilities.formatDate(new Date(ts), CONFIG.TZ, 'H'));
      if (hourCT >= 0 && hourCT < 5)  scores[email] += 3;
    }
  }

  // ── Score from Suspicious sheet ────────────────────────────────────────────
  if (shSusp && shSusp.getLastRow() > 1) {
    const rows = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, 3).getValues();
    for (const r of rows) {
      const ts     = r[0];
      const email  = String(r[1] || '').toLowerCase();
      const reason = String(r[2] || '');
      if (!email || new Date(ts) < cutoff) continue;
      ensure(email);

      if (reason === 'Impossible Travel') scores[email] += 20;
      if (reason === 'Login Burst')       scores[email] += 15;
    }
  }

  // Cap at 100
  Object.keys(scores).forEach(k => {
    scores[k] = Math.min(100, scores[k]);
  });

  return scores;
}

/**
 * Returns risk score for a single user. Called from LiveMap detail panel.
 */
function getUserRiskScore(email) {
  if (!email) return 0;
  const scores = getUserRiskScores();
  return scores[String(email).toLowerCase()] || 0;
}


/**
 * Returns week-over-week risk scores for a user.
 * Looks back up to 4 weeks using Main + Archive sheets.
 * Returns array of { week, score, label } objects, oldest first.
 */
function getUserRiskTrend(email) {
  if (!email) return [];
  email = String(email).toLowerCase();

  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shArch  = ss.getSheetByName(CONFIG.ARCHIVE);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);

  // Only look back 28 days — avoid reading huge archive sheets
  const cutoff28 = new Date(Date.now() - 28 * 24 * 3600000);

  // Read only cols A,B,C,P (ts, email, evName, outsideUS) — cols 1,2,3,16
  function getRows(sh) {
    if (!sh || sh.getLastRow() <= 1) return [];
    const vals = sh.getRange(2, 1, sh.getLastRow() - 1, 16).getValues();
    const out  = [];
    for (var i = 0; i < vals.length; i++) {
      var r = vals[i];
      if (String(r[1]||'').toLowerCase() !== email) continue;
      var ts = new Date(r[0]);
      if (ts < cutoff28) continue;
      out.push(r);
    }
    return out;
  }
  const allRows = getRows(shMain).concat(getRows(shArch));

  // Suspicious rows — cols A,B,C only
  function getSuspRows(sh) {
    if (!sh || sh.getLastRow() <= 1) return [];
    const vals = sh.getRange(2, 1, sh.getLastRow() - 1, 3).getValues();
    const out  = [];
    for (var i = 0; i < vals.length; i++) {
      var r = vals[i];
      if (String(r[1]||'').toLowerCase() !== email) continue;
      var ts = new Date(r[0]);
      if (ts < cutoff28) continue;
      out.push(r);
    }
    return out;
  }
  const suspRows = getSuspRows(shSusp);

  // Build 4 weekly buckets — current week first, going back
  const now    = new Date();
  const weeks  = [];
  for (var w = 3; w >= 0; w--) {
    var weekEnd   = new Date(now.getTime() - w * 7 * 24 * 3600000);
    var weekStart = new Date(weekEnd.getTime() - 7 * 24 * 3600000);
    weeks.push({ start: weekStart, end: weekEnd,
      label: 'Wk ' + Utilities.formatDate(weekStart, CONFIG.TZ, 'M/d') });
  }

  return weeks.map(function(wk) {
    var score = 0;

    // Score from login rows
    allRows.forEach(function(r) {
      var ts = new Date(r[0]);
      if (ts < wk.start || ts >= wk.end) return;
      var evName  = String(r[2] || '');
      var outside = r[15];
      if (evName === 'login_failure') score += 5;
      if (outside === true)           score += 10;
      var hourCT = Number(Utilities.formatDate(ts, CONFIG.TZ, 'H'));
      if (hourCT >= 0 && hourCT < 5) score += 3;
    });

    // Score from suspicious rows
    suspRows.forEach(function(r) {
      var ts = new Date(r[0]);
      if (ts < wk.start || ts >= wk.end) return;
      var reason = String(r[2] || '');
      if (reason === 'Impossible Travel') score += 20;
      if (reason === 'Login Burst')       score += 15;
    });

    score = Math.min(100, score);
    return { week: wk.label, score: score };
  });
}

/**
 * Returns top N users by risk score. Used by digest.
 */
function getTopRiskUsers(n) {
  n = n || 5;
  const scores = getUserRiskScores();
  return Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([email, score]) => ({ email, score }));
}

function getLiveMapData(opts) {
  _applyRuntimeConfig_();
  opts = opts || {};
  const maxRows   = Number(opts.maxRows)  || 2000;
  const eventType = opts.eventType        || 'all';  // all | success | failure
  const outsideUS = opts.outsideUS        === true;
  const ouFilter  = opts.ou               || '';
  const hoursBack = Number(opts.hoursBack)|| 0;      // 0 = all available

  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  if (!shMain || shMain.getLastRow() <= 1) return { rows: [], total: 0 };

  const data = shMain.getRange(2, 1, shMain.getLastRow() - 1, shMain.getLastColumn()).getValues();
  const cutoff = hoursBack > 0 ? new Date(Date.now() - hoursBack * 3600000) : null;

  const out = [];
  for (let i = data.length - 1; i >= 0 && out.length < maxRows; i--) {
    const r = data[i];
    const ts      = r[0];
    const email   = String(r[1]  || '');
    const evName  = String(r[2]  || '');
    const ip      = String(r[3]  || '');
    const city    = String(r[4]  || '');
    const region  = String(r[5]  || '');
    const country = String(r[6]  || '');
    const isp     = String(r[7]  || '');
    const latlng  = String(r[10] || '');
    const ou      = String(r[12] || '');
    const outsideUSFlag = r[15];

    if (!latlng || !latlng.includes(',')) continue;
    if (cutoff && new Date(ts) < cutoff) continue;
    if (eventType === 'success' && evName !== 'login_success') continue;
    if (eventType === 'failure' && evName !== 'login_failure') continue;
    if (outsideUS && !outsideUSFlag) continue;
    if (ouFilter && !String(ou).toLowerCase().startsWith(ouFilter.toLowerCase())) continue;

    const parts = latlng.split(',');
    out.push({
      ts:      Utilities.formatDate(new Date(ts), CONFIG.TZ, "yyyy-MM-dd HH:mm:ss"),
      email,
      evName,
      ip,
      city,
      region,
      country,
      isp,
      lat:     Number(parts[0]),
      lon:     Number(parts[1]),
      ou,
      outside: !!outsideUSFlag
    });
  }

  // Build chart stats from ALL rows (not just geo-tagged ones)
  // so trend charts reflect complete login data
  const chartDays  = {};
  const chartHours = Array(24).fill(0);
  for (let i = 0; i < data.length; i++) {
    const r      = data[i];
    const ts     = r[0];
    const evName = String(r[2] || '');
    if (!ts) continue;
    if (cutoff && new Date(ts) < cutoff) continue;
    if (eventType === 'success' && evName !== 'login_success') continue;
    if (eventType === 'failure' && evName !== 'login_failure') continue;
    const ouF = String(r[12] || '');
    if (ouFilter && !ouF.toLowerCase().startsWith(ouFilter.toLowerCase())) continue;

    const day = Utilities.formatDate(new Date(ts), CONFIG.TZ, 'yyyy-MM-dd');
    if (!chartDays[day]) chartDays[day] = { s: 0, f: 0, v: 0, p: 0 };
    if      (evName === 'login_success')   chartDays[day].s++;
    else if (evName === 'login_failure')   chartDays[day].f++;
    else if (evName === 'login_verification') chartDays[day].v++;
    else if (evName === 'password_edit' || evName === 'account_disabled_password_leak') chartDays[day].p++;
    chartHours[new Date(ts).getHours()]++;
  }

  // Include risk scores so the Intelligence tab matches the detail panel
  let riskScores = {};
  try { riskScores = getUserRiskScores(); } catch(e) {}
  return { rows: out, total: data.length, chartDays, chartHours, riskScores };
}

/**
 * Returns Active Now sheet rows for the live map Active Now mode.
 */
function getActiveNowMapData() {
  _applyRuntimeConfig_();
  const ss   = SpreadsheetApp.getActive();
  const shAN = ss.getSheetByName(CONFIG.ACTIVE);
  if (!shAN || shAN.getLastRow() <= 1) return { rows: [], total: 0 };

  const data = shAN.getRange(2, 1, shAN.getLastRow() - 1, shAN.getLastColumn()).getValues();
  const out  = [];

  for (const r of data) {
    const email    = String(r[0]  || '');
    const ou       = String(r[1]  || '');
    const firstSeen= String(r[2]  || '');
    const lastSeen = String(r[3]  || '');
    const count    = Number(r[6]  || 0);
    const lastIp   = String(r[7]  || '');
    const city     = String(r[8]  || '');
    const region   = String(r[9]  || '');
    const country  = String(r[10] || '');
    const isp      = String(r[11] || '');
    const latlng   = String(r[12] || '');
    const outsideUS= r[16];

    if (!latlng || !latlng.includes(',')) continue;
    const parts = latlng.split(',');

    out.push({
      email, ou, firstSeen, lastSeen, count,
      lastIp, city, region, country, isp,
      lat: Number(parts[0]),
      lon: Number(parts[1]),
      outside: !!outsideUS
    });
  }

  return { rows: out, total: out.length };
}

/**
 * Returns Suspicious sheet rows for the live map Suspicious mode.
 * Includes arc data for impossible travel events.
 */
function getSuspiciousMapData() {
  _applyRuntimeConfig_();
  const ss     = SpreadsheetApp.getActive();
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);
  if (!shSusp || shSusp.getLastRow() <= 1) return { rows: [], arcs: [] };

  // Build a key->latlng lookup from Main so Outside US and Burst rows get coordinates
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const keyToLL = {};
  if (shMain && shMain.getLastRow() > 1) {
    const mainData = shMain.getRange(2, 1, shMain.getLastRow() - 1, 11).getValues();
    for (const m of mainData) {
      const key   = String(m[9]  || ''); // Event Key (col 9)
      const latlng= String(m[10] || ''); // LatLng (col 10)
      if (key && latlng && latlng.includes(',')) keyToLL[key] = latlng;
    }
  }

  const data = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, shSusp.getLastColumn()).getValues();
  const rows = [];
  const arcs = [];

  for (const r of data) {
    const ts      = String(r[0]  || '');
    const email   = String(r[1]  || '');
    const reason  = String(r[2]  || '');
    const details = String(r[3]  || '');
    const fromCity= String(r[4]  || '');
    const fromReg = String(r[5]  || '');
    const fromCo  = String(r[6]  || '');
    const fromLL  = String(r[7]  || '');
    const toCity  = String(r[8]  || '');
    const toReg   = String(r[9]  || '');
    const toCo    = String(r[10] || '');
    const toLL    = String(r[11] || '');
    const dist    = r[12];
    const speed   = r[13];
    const keyA    = String(r[14] || '');
    const keyB    = String(r[15] || '');
    const severity= r[18];

    // For Outside US and Burst rows, look up coordinates from Main via Event Key
    let resolvedLL = fromLL;
    if (!resolvedLL || !resolvedLL.includes(',')) {
      resolvedLL = keyToLL[keyA] || keyToLL[keyB] || '';
    }

    rows.push({ ts, email, reason, details,
                fromCity, fromReg, fromCo,
                fromLL: resolvedLL,
                toCity, toReg, toCo, toLL,
                dist, speed, severity });

    // Build arc data for impossible travel
    if (reason === 'Impossible Travel' && fromLL && toLL &&
        fromLL.includes(',') && toLL.includes(',')) {
      const fp = fromLL.split(','), tp = toLL.split(',');
      arcs.push({
        email, details, dist, speed,
        from: { lat: Number(fp[0]), lon: Number(fp[1]), city: fromCity, region: fromReg, country: fromCo },
        to:   { lat: Number(tp[0]), lon: Number(tp[1]), city: toCity,   region: toReg,   country: toCo   }
      });
    }
  }

  return { rows, arcs };
}

/**
 * Returns the list of unique OUs from OUCache for the map OU filter dropdown.
 */
/**
 * Returns the ISO timestamp of the last successful sync.
 * Used by the Live Map toolbar to show "Synced X min ago".
 */
/**
 * Returns the count of users currently in the Active Now sheet.
 * Used by the Live Map Active Now scorecard.
 */
function getActiveNowCount() {
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.ACTIVE);
  if (!sh || sh.getLastRow() <= 1) return 0;
  return sh.getLastRow() - 1; // subtract header row
}

function getLastSyncTime() {
  const p = PropertiesService.getScriptProperties();
  // Prefer actual wall-clock sync time over the API window cursor
  return p.getProperty('lastSyncWallTime') || p.getProperty('lastRunISO') || '';
}

function getMapOUList() {
  _applyRuntimeConfig_();
  const res = getMonitorableOUs();
  return res.ous || [];
}

function doGet(e) {
  try {
    // Email-based access control — no token needed
    _requireAllowedUser_(); // throws if not authorized

    const tab = _getParam_(e, 'tab') || 'livemap';

    // Serve the full-screen live map HTML page
    if (tab === 'livemap' || tab === '') {
      return HtmlService.createHtmlOutputFromFile('LiveMap')
        .setTitle('Workspace Watchdog - Live Map')
        .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
    }

    const ss = SpreadsheetApp.getActive();
    const sh = ss.getSheetByName(tab);
    if (!sh) {
      return _json_({ ok: false, message: 'Unknown tab: ' + tab });
    }

    const lastRow = sh.getLastRow();
    const lastCol = sh.getLastColumn();
    if (lastRow < 2 || lastCol < 1) {
      return _json_({ ok: true, tab, rowCount: 0, rows: [] });
    }

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

function _requireAllowedUser_() {
  const email   = Session.getEffectiveUser().getEmail().toLowerCase().trim();
  const p       = PropertiesService.getScriptProperties();
  const allowed = (p.getProperty('MAP_ALLOWED_USERS') || '').toLowerCase();

  // If no allowed list configured, deny all access
  if (!allowed.trim()) {
    throw new Error('Access denied: MAP_ALLOWED_USERS is not configured. Add allowed email addresses in the Setup Wizard.');
  }

  const allowedList = allowed.split(/[,\n]/).map(function(e) { return e.trim(); }).filter(Boolean);

  if (!allowedList.includes(email)) {
    throw new Error('Access denied: ' + email + ' is not in the allowed users list. Contact your administrator.');
  }
}

// Kept for backwards compatibility — no longer used for auth
function _requireToken_(e) {
  _requireAllowedUser_();
}

function _json_(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
// ============================================================
// UPDATER — GitHub-based auto-update system
// Repo: https://github.com/fenman19/WorkspaceWatchdog
// ============================================================

const UPDATER = {
  REPO_RAW: 'https://raw.githubusercontent.com/fenman19/WorkspaceWatchdog/main',
  VERSION_URL: 'https://raw.githubusercontent.com/fenman19/WorkspaceWatchdog/main/version.json',
  FILES: [
    { name: 'Code',         filename: 'Code.gs',           type: 'SERVER_JS' },
    { name: 'SetupWizard',  filename: 'SetupWizard.html',  type: 'HTML'      },
    { name: 'Settings',     filename: 'Settings.html',     type: 'HTML'      },
    { name: 'Updates',      filename: 'Updates.html',      type: 'HTML'      },
    { name: 'LiveMap',      filename: 'LiveMap.html',       type: 'HTML'      }
  ],
  PROP_VERSION:    'WW_INSTALLED_VERSION',
  PROP_LAST_CHECK: 'WW_LAST_UPDATE_CHECK'
};

/** Returns the currently installed version string from Script Properties. */
function getInstalledVersion() {
  const v = PropertiesService.getScriptProperties().getProperty(UPDATER.PROP_VERSION);
  return v || '0.0.0';
}

/** Saves the installed version to Script Properties. */
function saveInstalledVersion(version) {
  PropertiesService.getScriptProperties().setProperty(UPDATER.PROP_VERSION, version);
}

/**
 * Fetches version.json from GitHub and returns
 * { installedVersion, latestVersion, changelog, upToDate, error }
 * Called from the Setup Wizard via google.script.run.
 */
function checkForUpdates() {
  try {
    const resp = UrlFetchApp.fetch(UPDATER.VERSION_URL, { muteHttpExceptions: true });
    if (resp.getResponseCode() !== 200) {
      return { error: 'Could not reach GitHub (HTTP ' + resp.getResponseCode() + '). Check your network or repo name.' };
    }
    const remote = JSON.parse(resp.getContentText());
    const installed = getInstalledVersion();

    PropertiesService.getScriptProperties().setProperty(
      UPDATER.PROP_LAST_CHECK,
      new Date().toISOString()
    );

    return {
      installedVersion: installed,
      latestVersion:    remote.version,
      released:         remote.released  || '',
      changelog:        remote.changelog || [],
      upToDate:         _versionCompare_(installed, remote.version) >= 0
    };
  } catch (e) {
    return { error: 'Update check failed: ' + e.message };
  }
}

/**
 * Fetches all project files from GitHub and rewrites this Apps Script
 * project using the Apps Script API. Returns { ok, message }.
 * Called from the Setup Wizard via google.script.run.
 */
function applyUpdate() {
  try {
    // 1. Fetch latest version info first
    const versionResp = UrlFetchApp.fetch(UPDATER.VERSION_URL, { muteHttpExceptions: true });
    if (versionResp.getResponseCode() !== 200) {
      return { ok: false, message: 'Could not fetch version info from GitHub.' };
    }
    const remote = JSON.parse(versionResp.getContentText());

    // 2. Fetch all source files from GitHub
    const requests = UPDATER.FILES.map(f => ({
      url: UPDATER.REPO_RAW + '/' + f.filename,
      muteHttpExceptions: true
    }));
    const responses = UrlFetchApp.fetchAll(requests);

    for (let i = 0; i < responses.length; i++) {
      if (responses[i].getResponseCode() !== 200) {
        return { ok: false, message: 'Failed to fetch ' + UPDATER.FILES[i].filename + ' from GitHub (HTTP ' + responses[i].getResponseCode() + ').' };
      }
    }

    // 3. Build the project content payload for the Apps Script API
    const files = UPDATER.FILES.map((f, i) => ({
      name:   f.name,
      type:   f.type,
      source: responses[i].getContentText()
    }));

    // Also fetch appsscript.json if present
    try {
      const manifestResp = UrlFetchApp.fetch(
        UPDATER.REPO_RAW + '/appsscript.json',
        { muteHttpExceptions: true }
      );
      if (manifestResp.getResponseCode() === 200) {
        files.push({
          name:   'appsscript',
          type:   'JSON',
          source: manifestResp.getContentText()
        });
      }
    } catch(e) { /* manifest optional */ }

    // 4. Call Apps Script API to overwrite the project
    const scriptId = ScriptApp.getScriptId();
    const token    = ScriptApp.getOAuthToken();
    const apiUrl   = 'https://script.googleapis.com/v1/projects/' + scriptId + '/content';

    const apiResp = UrlFetchApp.fetch(apiUrl, {
      method:  'PUT',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type':  'application/json'
      },
      payload:            JSON.stringify({ files }),
      muteHttpExceptions: true
    });

    const apiCode = apiResp.getResponseCode();
    if (apiCode !== 200) {
      const body = apiResp.getContentText();
      // Friendly message for the most common failure
      if (body.indexOf('Apps Script API has not been used') !== -1 ||
          body.indexOf('accessNotConfigured') !== -1) {
        return {
          ok: false,
          message: 'ENABLE_API',  // sentinel — wizard shows setup instructions
          scriptId: scriptId
        };
      }
      return { ok: false, message: 'Apps Script API returned HTTP ' + apiCode + ': ' + body };
    }

    // 5. Save new version to Script Properties
    saveInstalledVersion(remote.version);

    return {
      ok:      true,
      message: 'Successfully updated to v' + remote.version + '. Please reload the spreadsheet.',
      version: remote.version
    };

  } catch (e) {
    return { ok: false, message: 'Update failed: ' + e.message };
  }
}


/**
 * Lightweight notification check for the Live Map.
 * Returns update status and license info in a single call.
 * Uses cached last-check result to avoid hammering GitHub on every map load.
 * Called via google.script.run from LiveMap.html on load.
 */
function getMapNotifications() {
  const props = PropertiesService.getScriptProperties();
  const result = {
    updateAvailable:  false,
    latestVersion:    null,
    installedVersion: getInstalledVersion(),
    licenseExpiring:  false,
    licenseExpired:   false,
    licenseDaysLeft:  null,
    licenseTier:      props.getProperty('WW_LICENSE_TIER') || 'free'
  };

  // ── Update check — use cached result if checked within last 6 hours ──
  const lastCheck  = props.getProperty(UPDATER.PROP_LAST_CHECK);
  const sixHoursMs = 6 * 60 * 60 * 1000;
  const needsCheck = !lastCheck ||
    (Date.now() - new Date(lastCheck).getTime()) > sixHoursMs;

  if (needsCheck) {
    try {
      const resp = UrlFetchApp.fetch(UPDATER.VERSION_URL, {
        muteHttpExceptions: true,
        deadline: 5  // 5 second timeout — don't hold up the map
      });
      if (resp.getResponseCode() === 200) {
        const remote = JSON.parse(resp.getContentText());
        props.setProperty(UPDATER.PROP_LAST_CHECK, new Date().toISOString());
        props.setProperty('WW_LATEST_VERSION', remote.version);
        result.latestVersion    = remote.version;
        result.updateAvailable  = _versionCompare_(result.installedVersion, remote.version) < 0;
      }
    } catch(e) { /* silent — don't block map load */ }
  } else {
    // Use cached latest version
    const cached = props.getProperty('WW_LATEST_VERSION');
    if (cached) {
      result.latestVersion   = cached;
      result.updateAvailable = _versionCompare_(result.installedVersion, cached) < 0;
    }
  }

  // ── License expiry check ──
  // Will be wired to real license data when Cloudflare Worker is built.
  // For now reads from Script Properties if manually set.
  const expiryStr = props.getProperty('WW_LICENSE_EXPIRY');
  if (expiryStr) {
    const expiry   = new Date(expiryStr);
    const daysLeft = Math.ceil((expiry - Date.now()) / (1000 * 60 * 60 * 24));
    result.licenseDaysLeft = daysLeft;
    if (daysLeft <= 0)  result.licenseExpired  = true;
    else if (daysLeft <= 30) result.licenseExpiring = true;
  }

  return result;
}
/**
 * Simple semver comparator. Returns negative if a < b, 0 if equal, positive if a > b.
 */
function _versionCompare_(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Opens the Setup Wizard scrolled to / highlighting the Updates card.
 * Added to menu as "Check for Updates".
 */
function showUpdatesPanel() {
  const html = HtmlService.createHtmlOutputFromFile('Updates')
    .setTitle('Workspace Watchdog — Updates')
    .setWidth(620)
    .setHeight(580);
  SpreadsheetApp.getUi().showModalDialog(html, 'Workspace Watchdog — Updates');
}
