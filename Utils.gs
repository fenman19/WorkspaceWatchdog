/* global AdminReports, AdminDirectory */
/**
 * Utils.gs — Shared constants, CONFIG, headers, cache indexes, and utility functions.
 * All other .gs files reference these globals freely (shared scope in Apps Script).
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
  FAST_INSTALL_LOOKBACK_MINUTES: 120,
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
  KEEP_DAYS: 7,
  TRIM_AFTER_SYNC: true,
  // Background cache warmup
  CACHE_WARMUP_BATCH_IP: 10,
  CACHE_WARMUP_BATCH_USER: 10,
  CACHE_WARMUP_INTERVAL_MINUTES: 5,
  // OU filtering
  MONITOR_OUS: '',
  BULK_OU_LOAD: true,
  // Google Chat alerts
  CHAT_ALERT_DEDUPE_HOURS: 12,
  CHAT_ALERT_ON_OUTSIDE_US: true,
  CHAT_ALERT_ON_OUTSIDE_SAFE_STATES: true,
  CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: true,
  CHAT_ALERT_ON_BURST: true,
  CHAT_ALERT_ON_PASSWORD_LEAK: true,
  CHAT_ALERT_ON_FAIL_THRESHOLD: true,
  FAIL_THRESHOLD_COUNT: 10,
  CHAT_ALERT_SCHEDULED_ONLY: true,
  // Daily/weekly digest
  DIGEST_ENABLED: false,
  DIGEST_HOUR: 7,
  DIGEST_EMAIL_ENABLED: true,
  DIGEST_EMAIL_TO: '',
  WEEKLY_REPORT_ENABLED: true,
  DIGEST_COMPARISON: true,
  // IP Reputation
  IP_REP_ENABLED: false,
  IP_REP_MIN_SCORE: 25,
  IP_REP_CACHE_DAYS: 3,
  // Campus IP Filter
  CAMPUS_IP_FILTER: '',
  // Mobile/cellular IP filtering
  IGNORE_MOBILE_IMPOSSIBLE_TRAVEL: true,
  IGNORE_MOBILE_STATE_MONITORING: true,
  MOBILE_ISP_LIST: '',
  // U.S. state monitoring — when enabled, successful U.S. logins from any
  // recognized state NOT listed in SAFE_STATES are treated as suspicious.
  STATE_MONITORING_ENABLED: false,
  SAFE_STATES: '',
  // Timestamp captured when State Monitoring is enabled. Only login events at
  // or after this time are eligible for Outside Safe States detection.
  STATE_MONITORING_START_ISO: ''
};

// Exact-match ISP names (case-insensitive) to treat as mobile/cellular for
// Impossible Travel suppression. Populated from the admin-selected checkboxes
// in Settings (backed by the MOBILE_ISP_LIST script property) — see Geo.gs
// getKnownIsps() / DEFAULT_MOBILE_ISPS for the picker that builds this list.
// Exact match (not substring) is used deliberately: an admin checking
// "Verizon Business" should not also silently suppress an unrelated ISP that
// merely contains the word "Verizon".
function _splitMobileIspList_(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return [];
  // Pipe is canonical because commas are valid characters in ISP names.
  // Fall back to the legacy comma format so existing deployments keep working
  // until the list is next saved from Settings.
  const parts = raw.indexOf('|') >= 0 ? raw.split('|') : raw.split(',');
  return parts.map(s => s.trim()).filter(Boolean);
}

function _mobileIspSet_() {
  const set = new Set();
  _splitMobileIspList_(CONFIG.MOBILE_ISP_LIST).forEach(s => {
    const v = s.toLowerCase();
    if (v) set.add(v);
  });
  return set;
}

function _isMobileIsp_(isp) {
  if (!isp) return false;
  if (!CONFIG.MOBILE_ISP_LIST) return false;
  return _mobileIspSet_().has(String(isp).trim().toLowerCase());
}

// Normalize U.S. state/region values returned by different geo providers.
// ipapi.co generally returns two-letter codes, while IPinfo/freeipapi may return
// full state names. Unknown/blank regions intentionally return an empty string
// so incomplete geo data does not create notification noise.
const US_STATE_NAME_TO_CODE = {
  'alabama':'AL','alaska':'AK','arizona':'AZ','arkansas':'AR','california':'CA',
  'colorado':'CO','connecticut':'CT','delaware':'DE','florida':'FL','georgia':'GA',
  'hawaii':'HI','idaho':'ID','illinois':'IL','indiana':'IN','iowa':'IA','kansas':'KS',
  'kentucky':'KY','louisiana':'LA','maine':'ME','maryland':'MD','massachusetts':'MA',
  'michigan':'MI','minnesota':'MN','mississippi':'MS','missouri':'MO','montana':'MT',
  'nebraska':'NE','nevada':'NV','new hampshire':'NH','new jersey':'NJ','new mexico':'NM',
  'new york':'NY','north carolina':'NC','north dakota':'ND','ohio':'OH','oklahoma':'OK',
  'oregon':'OR','pennsylvania':'PA','rhode island':'RI','south carolina':'SC',
  'south dakota':'SD','tennessee':'TN','texas':'TX','utah':'UT','vermont':'VT',
  'virginia':'VA','washington':'WA','west virginia':'WV','wisconsin':'WI','wyoming':'WY',
  'district of columbia':'DC','washington, d.c.':'DC','washington dc':'DC'
};
const US_STATE_CODES = new Set(Object.keys(US_STATE_NAME_TO_CODE).map(k => US_STATE_NAME_TO_CODE[k]));

function _normalizeUsStateCode_(region) {
  const raw = String(region || '').trim();
  if (!raw) return '';
  const upper = raw.toUpperCase();
  if (US_STATE_CODES.has(upper)) return upper;
  return US_STATE_NAME_TO_CODE[raw.toLowerCase()] || '';
}

function _splitSafeStateList_(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return [];
  return raw.split(/[|,;\n]+/).map(s => _normalizeUsStateCode_(s)).filter(Boolean);
}

function _safeStateSet_() {
  return new Set(_splitSafeStateList_(CONFIG.SAFE_STATES));
}

function _stateMonitoringStartMs_() {
  const raw = String(CONFIG.STATE_MONITORING_START_ISO || '').trim();
  if (!raw) return NaN;
  const ms = new Date(raw).getTime();
  return isFinite(ms) ? ms : NaN;
}

function _isStateMonitoringEventEligible_(eventTs) {
  if (!CONFIG.STATE_MONITORING_ENABLED) return false;
  const startMs = _stateMonitoringStartMs_();
  if (!isFinite(startMs)) return false;
  const eventMs = eventTs instanceof Date ? eventTs.getTime() : new Date(eventTs).getTime();
  return isFinite(eventMs) && eventMs >= startMs;
}

function _isOutsideSafeStates_(country, region, eventTs) {
  if (!_isStateMonitoringEventEligible_(eventTs)) return false;
  if (String(country || '').trim().toUpperCase() !== 'US') return false;
  const stateCode = _normalizeUsStateCode_(region);
  if (!stateCode) return false;
  return !_safeStateSet_().has(stateCode);
}

// ===== Cache Indexes (large-domain performance) ==============================
var __GEO_INDEX = null;      // IP  -> geo object
var __OU_INDEX  = null;      // email (lower) -> {ou, lastSeenISO}
var __GEO_ROW_INDEX = null;  // IP  -> 1-based sheet row number (skips header)
var __OU_ROW_INDEX  = null;  // email (lower) -> 1-based sheet row number

// ===== Headers (PRECOMPUTED FIELDS APPENDED) =================================
const MAIN_HEADERS = [
  'Timestamp','Actor Email','Event Name','IP','City','Region','Country','ISP','Raw JSON','Event Key',
  'LatLng','GeoSource','Org Unit Path',
  'ParsedTSNoTZ','HourBucket','OutsideUS','HasGeo','TopOU'
];
const GEO_HEADERS = ['IP','City','Region','Country','ISP','Latitude','Longitude','Source','LastSeenISO'];
const OU_HEADERS  = ['Email','OrgUnitPath','LastSeenISO'];

const ACTIVE_HEADERS = [
  'Email','OU','FirstSeen (CT)','LastSeen (CT)','Sources','WindowMin','Count',
  'Last IP','City','Region','Country','ISP','LatLng','GeoSource',
  'LastSeenNoTZ','HourBucket','AN_OutsideUS','AN_HasGeo'
];

const SUSP_HEADERS  = [
  'Timestamp (CT)','Actor Email','Reason','Details',
  'From City','From Region','From Country','From LatLng',
  'To City','To Region','To Country','To LatLng',
  'Distance (mi)','Speed (mph)','EventKey A','EventKey B',
  'SuspNoTZ','HourBucket','Severity',
  'From IP','From ISP','To IP','To ISP',
  'Alerted'
];
const SUSP_ALERTED_COL = 24; // 1-based column index of Alerted

const DIAG_HEADERS = [
  'Trigger','Start (CT)','End (CT)','Events Parsed','Rows Appended','Notes',
  'LagMin','OverlapMin','NewRows','DupesInWindow',
  'MainRowsBefore','MainRowsAfter','DedupeRemoved',
  'TrimArchived','TrimKept',
  'WindowStartISO','WindowEndISO'
];

const WW_MONITOR_VERSION = '3.7.00';

// ===== KeyIndex Sheet =========================================================
const KEY_INDEX_SHEET = 'KeyIndex';
var __KEY_INDEX = null;

// ===== OU Map Singleton =======================================================
var __OU_MAP_CACHE = null;
function __getOUMap() {
  if (!__OU_MAP_CACHE) {
    __OU_MAP_CACHE = _loadOUMap_();
    __OU_INDEX = __OU_MAP_CACHE; // keep both in sync
  }
  return __OU_MAP_CACHE;
}

// ===== Whitelist Cache ========================================================
var __WHITELIST = null;

// ===== OU Overrides ===========================================================
const OU_OVERRIDES = {
  'help.desk@dawsonesc.com': '/NonUserAccounts',
};

// ===== Runtime Config =========================================================
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
  CONFIG.CHAT_ALERT_ON_OUTSIDE_SAFE_STATES = bool('CHAT_ALERT_ON_OUTSIDE_SAFE_STATES', CONFIG.CHAT_ALERT_ON_OUTSIDE_SAFE_STATES);
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
  CONFIG.CAMPUS_IP_FILTER                = str ('CAMPUS_IP_FILTER',                CONFIG.CAMPUS_IP_FILTER);
  CONFIG.IGNORE_MOBILE_IMPOSSIBLE_TRAVEL  = bool('IGNORE_MOBILE_IMPOSSIBLE_TRAVEL',  CONFIG.IGNORE_MOBILE_IMPOSSIBLE_TRAVEL);
  CONFIG.IGNORE_MOBILE_STATE_MONITORING   = bool('IGNORE_MOBILE_STATE_MONITORING',   CONFIG.IGNORE_MOBILE_STATE_MONITORING);
  CONFIG.MOBILE_ISP_LIST                  = str ('MOBILE_ISP_LIST',                 CONFIG.MOBILE_ISP_LIST);
  CONFIG.STATE_MONITORING_ENABLED         = bool('STATE_MONITORING_ENABLED',         CONFIG.STATE_MONITORING_ENABLED);
  CONFIG.SAFE_STATES                      = str ('SAFE_STATES',                      CONFIG.SAFE_STATES);
  CONFIG.STATE_MONITORING_START_ISO       = str ('STATE_MONITORING_START_ISO',       CONFIG.STATE_MONITORING_START_ISO);

  // Upgrade safety: older State Monitoring builds did not have a start marker
  // and would retroactively flag every retained Main row. If this deployment
  // is already enabled but has no marker, establish one now so only events
  // from this code activation forward are considered by the state rule.
  if (CONFIG.STATE_MONITORING_ENABLED && !CONFIG.STATE_MONITORING_START_ISO) {
    const nowIso = new Date().toISOString();
    p.setProperty('STATE_MONITORING_START_ISO', nowIso);
    CONFIG.STATE_MONITORING_START_ISO = nowIso;
  }
}

// ===== Cache Reset ============================================================
function _resetAllCaches_() {
  __GEO_INDEX     = null;
  __OU_INDEX      = null;
  __GEO_ROW_INDEX = null;
  __OU_ROW_INDEX  = null;
  __OU_MAP_CACHE  = null;
  __KEY_INDEX     = null;
  __WHITELIST      = null;
}

// ===== Sheet Utilities ========================================================
function _ensureAllSheets() {
  const ss = SpreadsheetApp.getActive();
  [CONFIG.MAIN, CONFIG.GEOCACHE, CONFIG.OU_CACHE, CONFIG.ACTIVE, CONFIG.SUSPICIOUS, CONFIG.DIAG, CONFIG.ARCHIVE, 'Setup']
    .forEach(n => { if (!ss.getSheetByName(n)) ss.insertSheet(n); });
  if (!ss.getSheetByName(KEY_INDEX_SHEET)) {
    const ki = ss.insertSheet(KEY_INDEX_SHEET);
    ki.hideSheet();
  }
}

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

// ===== Key Index ==============================================================
function _loadKeyIndex_() {
  if (__KEY_INDEX) return __KEY_INDEX;
  const ss = SpreadsheetApp.getActive();
  let sh = ss.getSheetByName(KEY_INDEX_SHEET);
  if (!sh) { sh = ss.insertSheet(KEY_INDEX_SHEET); sh.hideSheet(); }
  const last = sh.getLastRow();
  if (last < 1) { __KEY_INDEX = new Set(); return __KEY_INDEX; }
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
  SpreadsheetApp.getActive().toast('KeyIndex rebuilt with ' + keys.length + ' keys.', 'Workspace Watchdog', 5);
}

// ===== OU Helpers =============================================================
function _normalizeOU_(v) {
  if (v === null || v === undefined) return '/';
  if (Object.prototype.toString.call(v) === '[object Date]') return '/';
  const s = String(v).trim();
  if (s === '' || s === '/') return '/';
  if (/^\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}$/.test(s)) return '/';
  return s.startsWith('/') ? s : '/' + s;
}

function _resolveOU_(email, ou) {
  const e = String(email || '').toLowerCase().trim();
  if (OU_OVERRIDES && OU_OVERRIDES[e]) return OU_OVERRIDES[e];
  return _normalizeOU_(ou);
}

function _asTextLiteral_(v) {
  if (v === null || v === undefined) return '';
  if (Object.prototype.toString.call(v) === '[object Date]') {
    const d = v, y = d.getFullYear(), m = d.getMonth()+1, dd = d.getDate();
    v = y + '-' + (m<10?'0':'') + m + '-' + (dd<10?'0':'') + dd;
  }
  const s = String(v);
  return s === '' ? '' : "'" + s;
}

function _topOU_(path) {
  if (!path) return "(none)";
  var s = String(path);
  if (s === "/") return "(none)";
  var parts = s.split("/");
  return parts.length > 1 && parts[1] ? parts[1] : "(none)";
}

// ===== Math / Formatting Helpers ==============================================
function _mkKey_(s) { return Utilities.base64EncodeWebSafe(s).slice(0, 44); }

function _fmtLatLng_(lat, lon) {
  const la = _num(lat), lo = _num(lon);
  if (la === '' || lo === '') return '';
  return la + ',' + lo;
}

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

// ===== Retry / API Helpers ====================================================
function _sleep(ms) { Utilities.sleep(ms || 200); }

function _withRetries_(label, maxAttempts, fn) {
  maxAttempts = Math.max(1, Number(maxAttempts) || 4);
  var attempt = 0, lastErr;
  while (attempt < maxAttempts) {
    try {
      return fn();
    } catch (e) {
      lastErr = e;
      var msg = (e && e.message) ? e.message : String(e);
      var retryable = /Empty response|Internal error|Backend Error|Service unavailable|429|5\d\d/i.test(msg);
      if (!retryable) throw e;
      var delay = Math.min(8000, Math.pow(2, attempt) * 500);
      _sleep(delay);
      attempt++;
    }
  }
  throw lastErr;
}

function _reportsListSafe_(userKey, appName, params) {
  return _withRetries_('reports.list ' + appName, 5, function() {
    var resp = AdminReports.Activities.list(userKey, appName, params);
    if (!resp || typeof resp !== 'object') throw new Error('Empty response');
    return resp;
  });
}

// ===== Trigger Helpers ========================================================
function _deleteMyTriggers_() {
  try {
    const me = ScriptApp.getProjectTriggers();
    me.forEach(function(t) {
      if (['scheduledSync','weeklyReset','cacheWarmup','dailyDigest','weeklyReport','autoRetryFailedGeo'].includes(t.getHandlerFunction())) {
        ScriptApp.deleteTrigger(t);
      }
    });
  } catch (e) {
    _logDiagnostics('install/_deleteMyTriggers_', new Date(), new Date(), 0, 0,
      'Skip trigger cleanup: ' + (e && e.message ? e.message : e));
  }
}

// ===== Menu Wrappers (trigger-called functions) ===============================
function weeklyReset() {
  _applyRuntimeConfig_();
  trimMainRolling();
  _cleanupAlertKeys_();
}

function rebuildActiveNow() { _refreshActiveNow_(Number(CONFIG.ACTIVE_WINDOW_MINUTES || 30)); }
function rebuildActiveNow30() { _refreshActiveNow_(30); }
function rebuildActiveNow60() { _refreshActiveNow_(60); }
