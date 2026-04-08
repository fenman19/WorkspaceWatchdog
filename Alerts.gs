/* global AdminReports, AdminDirectory */
/**
 * Alerts.gs — Google Chat webhook alerts, dedup (Script Properties + Cache),
 *              whitelist management, and all alert type functions.
 */

// ===== Core Sender ============================================================

function sendChatAlert_(text) {
  const url = PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL');
  if (!url) return;
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
    _logDiagnostics('sendChatAlert_/exception', new Date(), new Date(), 0, 0,
      (e && e.message ? e.message : String(e)));
  }
}

function _sendAlertOnce_(cacheKey, text) {
  const p   = PropertiesService.getScriptProperties();
  const c   = CacheService.getScriptCache();
  const raw = 'ww_alert_' + String(cacheKey).replace(/[^a-zA-Z0-9_]/g, '_');
  const k   = raw.slice(0, 240);
  const now = Date.now();
  const ttlMs  = Math.max(3600000, (CONFIG.CHAT_ALERT_DEDUPE_HOURS || 12) * 3600000);
  const ttlSec = Math.min(21600, Math.floor(ttlMs / 1000));

  if (c.get(k)) {
    _logDiagnostics('alertDedup/cache', new Date(), new Date(), 0, 0, 'Suppressed (cache): ' + raw.slice(0, 80));
    return;
  }

  const existing = p.getProperty(k);
  if (existing) {
    try {
      if (now - Number(existing) < ttlMs) {
        _logDiagnostics('alertDedup/props', new Date(), new Date(), 0, 0, 'Suppressed (props): ' + raw.slice(0, 80));
        c.put(k, '1', ttlSec);
        return;
      }
    } catch(_) { return; }
  }

  p.setProperty(k, String(now));
  c.put(k, '1', ttlSec);
  sendChatAlert_(text);
}

function _alertsEnabled_(triggerName) {
  if (!PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL')) return false;
  if (CONFIG.CHAT_ALERT_SCHEDULED_ONLY && triggerName !== 'scheduledSync') return false;
  return true;
}

// ===== Alert Key Cleanup ======================================================

function _cleanupAlertKeys_() {
  try {
    const p      = PropertiesService.getScriptProperties();
    const all    = p.getKeys();
    const cutoff = Date.now() - 30 * 24 * 3600000;
    let   deleted = 0;
    all.forEach(k => {
      if (!k.startsWith('ww_alert_') && !k.startsWith('ww_alerted_') && !k.startsWith('ww_chat_digest_') && !k.startsWith('ww_weekly_report_')) return;
      try {
        const val = p.getProperty(k);
        const ts  = Number(val);
        const tsMs = isFinite(ts) ? ts : new Date(val).getTime();
        if (isFinite(tsMs) && tsMs < cutoff) { p.deleteProperty(k); deleted++; }
      } catch(e) {}
    });
    if (deleted > 0) {
      _logDiagnostics('alertKeyCleanup', new Date(), new Date(), deleted, 0,
        'Deleted ' + deleted + ' expired alert dedup key(s) from Script Properties.');
    }
  } catch(e) {}
  try { trimDiagnosticsSheet(); } catch(e) {}
}

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

// ===== Permanent Alert Dedup ==================================================

function _isAlertedPermanently_(key) {
  const p = PropertiesService.getScriptProperties();
  const k = 'ww_alerted_' + String(key).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 200);
  const found = p.getProperty(k) !== null;
  if (!found) _logDiagnostics('permDedup/check', new Date(), new Date(), 0, 0, 'NOT FOUND: ' + k.slice(0, 120));
  return found;
}

function _markAlertedPermanently_(key) {
  const p = PropertiesService.getScriptProperties();
  const k = 'ww_alerted_' + String(key).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 200);
  try {
    p.setProperty(k, String(Date.now()));
    _logDiagnostics('permDedup/mark', new Date(), new Date(), 0, 0, 'MARKED: ' + k.slice(0, 120));
  } catch(e) {
    _logDiagnostics('permDedup/error', new Date(), new Date(), 0, 0,
      'FAILED to mark: ' + k.slice(0, 120) + ' | ' + (e.message || String(e)));
  }
}

// ===== Alert Types ============================================================

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
    const ts = r[0], email = String(r[1] || '').toLowerCase(), evName = String(r[2] || '');
    if (!email || !ts || new Date(ts) < cutoff) continue;
    if (evName !== 'login_failure') continue;
    failCounts[email] = (failCounts[email] || 0) + 1;
  }
  Object.entries(failCounts).forEach(([email, count]) => {
    if (count < CONFIG.FAIL_THRESHOLD_COUNT) return;
    if (_isWhitelisted_(email, null)) return;
    const cacheKey = 'failthresh_' + email + '_' + Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd');
    const msg =
      'Failed Login Threshold Exceeded\n' +
      'User:      ' + email + '\n' +
      'Failures:  ' + count + ' in the last 24 hours\n' +
      'Threshold: ' + CONFIG.FAIL_THRESHOLD_COUNT + '\n' +
      'Note: This may indicate a slow brute-force attack.';
    _sendAlertOnce_(cacheKey, msg);
  });
}

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

function _maybeAlertOutsideUS_(triggerName, r, g) {
  if (!CONFIG.CHAT_ALERT_ON_OUTSIDE_US) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(r.email, r.ip)) return;
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

function _maybeAlertImpossibleTravel_(triggerName, email, a, b, miles, mph) {
  if (!CONFIG.CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(email, a.ip) || _isWhitelisted_(email, b.ip)) return;
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

function _maybeAlertLoginBurst_(triggerName, email, count, windowMin, firstTs, lastTs, firstKey, lastKey) {
  if (!CONFIG.CHAT_ALERT_ON_BURST) return;
  if (!_alertsEnabled_(triggerName)) return;
  if (_isWhitelisted_(email, null)) return;
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

// ===== Chat Settings & Test ===================================================

function saveChatSettings(webhookUrl, dedupeHours, onOutsideUS, onTravel, onBurst, scheduledOnly) {
  const p = PropertiesService.getScriptProperties();
  if (webhookUrl && webhookUrl.trim()) p.setProperty('CHAT_WEBHOOK_URL', webhookUrl.trim());
  p.setProperties({
    CHAT_ALERT_DEDUPE_HOURS:         String(Number(dedupeHours) || 12),
    CHAT_ALERT_ON_OUTSIDE_US:        String(!!onOutsideUS),
    CHAT_ALERT_ON_IMPOSSIBLE_TRAVEL: String(!!onTravel),
    CHAT_ALERT_ON_BURST:             String(!!onBurst),
    CHAT_ALERT_SCHEDULED_ONLY:       String(!!scheduledOnly)
  });
  _applyRuntimeConfig_();
  return { ok: true };
}

function testChatAlertWithUrl(webhookUrl) {
  if (!webhookUrl || !webhookUrl.trim()) throw new Error('No webhook URL provided.');
  PropertiesService.getScriptProperties().setProperty('CHAT_WEBHOOK_URL', webhookUrl.trim());
  _applyRuntimeConfig_();
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
    SpreadsheetApp.getUi().alert('No webhook URL set.', 'Add CHAT_WEBHOOK_URL to Script Properties first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }
  sendChatAlert_('Workspace Watchdog v' + WW_MONITOR_VERSION + ': Google Chat webhook is working.');
  SpreadsheetApp.getActive().toast('Test alert sent.', 'Workspace Watchdog', 5);
}

// ===== Whitelist ==============================================================

function _loadWhitelist_() {
  if (__WHITELIST) return __WHITELIST;
  const raw = PropertiesService.getScriptProperties().getProperty('SUSPICIOUS_WHITELIST') || '';
  const emails = new Set();
  const ips    = new Set();
  raw.split(/[\n\r,]+/).forEach(entry => {
    const e = entry.trim().toLowerCase();
    if (!e) return;
    if (e.includes('@')) { emails.add(e); } else { ips.add(e); }
  });
  __WHITELIST = { emails, ips };
  return __WHITELIST;
}

function _isWhitelisted_(email, ip) {
  const wl = _loadWhitelist_();
  if (email && wl.emails.has(String(email).toLowerCase().trim())) return true;
  if (ip    && wl.ips.has(String(ip).trim()))                      return true;
  return false;
}

function saveWhitelist(raw) {
  const entries = String(raw || '').replace(/,/g, '\n').split('\n').map(e => e.trim()).filter(Boolean);
  PropertiesService.getScriptProperties().setProperty('SUSPICIOUS_WHITELIST', entries.join('\n'));
  __WHITELIST = null;
  const emails = entries.filter(e => e.includes('@')).length;
  const ips    = entries.length - emails;
  return { ok: true, emailCount: emails, ipCount: ips };
}

function getWhitelist() {
  return PropertiesService.getScriptProperties().getProperty('SUSPICIOUS_WHITELIST') || '';
}

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
  if (existing.indexOf(entry) >= 0) return { ok: true, message: entry + ' already in whitelist.' };
  existing.push(entry);
  p.setProperty('SUSPICIOUS_WHITELIST', existing.join('\n'));
  __WHITELIST = null;
  return { ok: true, message: entry + ' added to whitelist.' };
}

// ===== Map Access Control =====================================================

function getMapAllowedUsers() {
  return PropertiesService.getScriptProperties().getProperty('MAP_ALLOWED_USERS') || '';
}

function saveMapAllowedUsers(raw) {
  const cleaned = (raw || '').split(/[,\n]/)
    .map(function(e) { return e.trim().toLowerCase(); })
    .filter(Boolean).join('\n');
  PropertiesService.getScriptProperties().setProperty('MAP_ALLOWED_USERS', cleaned);
  return { ok: true, count: cleaned ? cleaned.split('\n').length : 0 };
}

function _requireAllowedUser_() {
  const email   = Session.getEffectiveUser().getEmail().toLowerCase().trim();
  const p       = PropertiesService.getScriptProperties();
  const allowed = (p.getProperty('MAP_ALLOWED_USERS') || '').toLowerCase();
  if (!allowed.trim()) {
    throw new Error('Access denied: MAP_ALLOWED_USERS is not configured. Add allowed email addresses in the Setup Wizard.');
  }
  const allowedList = allowed.split(/[,\n]/).map(function(e) { return e.trim(); }).filter(Boolean);
  if (!allowedList.includes(email)) {
    throw new Error('Access denied: ' + email + ' is not in the allowed users list. Contact your administrator.');
  }
}

function _requireToken_(e) {
  _requireAllowedUser_();
}
