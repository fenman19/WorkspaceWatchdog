/* global AdminReports, AdminDirectory */
/**
 * Google Workspace Login Monitor v3.2.0
 * Added Logo to Daily Digest and Weekly Summary
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

    // Header with logo
    '<tr><td style="background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 50%,#0a1628 100%);padding:28px 24px 20px;text-align:center;"><img src="data:image/png;base64,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" width="100" height="120" alt="Workspace Watchdog" style="display:block;margin:0 auto 12px;"/><div style="font-family:Arial,sans-serif;font-size:22px;font-weight:700;color:#00c8ff;letter-spacing:2px;text-transform:uppercase;text-shadow:0 0 20px rgba(0,200,255,0.5);">Workspace Watchdog</div></td></tr>',
    '<tr><td style="background:#1a2e45;padding:16px 24px 20px;text-align:center;">',
    '<div style="font-size:20px;font-weight:700;color:#e8eaed;">Weekly Security Report</div>',
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

    // Header with logo
    '<tr><td style="background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 50%,#0a1628 100%);padding:28px 24px 20px;text-align:center;"><img src="data:image/png;base64,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" width="100" height="120" alt="Workspace Watchdog" style="display:block;margin:0 auto 12px;"/><div style="font-family:Arial,sans-serif;font-size:22px;font-weight:700;color:#00c8ff;letter-spacing:2px;text-transform:uppercase;text-shadow:0 0 20px rgba(0,200,255,0.5);">Workspace Watchdog</div></td></tr>',
    '<tr><td style="background:#1a2e45;padding:16px 24px 20px;text-align:center;">',
    '<div style="font-size:20px;font-weight:700;color:#e8eaed;">Daily Security Digest</div>',
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
