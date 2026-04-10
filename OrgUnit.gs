/* global AdminReports, AdminDirectory */
/**
 * OrgUnit.gs — OU system: cache load/upsert, bulk Directory load, OU filter, batch writer.
 */

function _getOUForEmail_(email) {
  try {
    if (!email) return '';
    var u = AdminDirectory.Users.get(email);
    return (u && u.orgUnitPath) ? String(u.orgUnitPath) : '';
  } catch (e) { return ''; }
}

// Builds and caches the full OU map from OUCache sheet.
// Any callers passing shOU as an arg are safe — the singleton __OU_INDEX is always used.
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
    rowIdx[email] = i + 2;
  }
  __OU_INDEX = map;
  __OU_ROW_INDEX = rowIdx;
  __OU_MAP_CACHE = map; // keep singleton in sync so __getOUMap() doesn't re-read the sheet
  return map;
}

function _isFreshOU_(o) {
  if (!o || !o.lastSeenISO) return false;
  const ageH = (Date.now() - new Date(o.lastSeenISO).getTime())/3600000;
  return ageH < CONFIG.OU_TTL_HOURS;
}

function _upsertOURow_(shOU, email, obj) {
  if (!__OU_ROW_INDEX) __OU_ROW_INDEX = {};
  const key = String(email || '').toLowerCase();
  const existingRow = __OU_ROW_INDEX[key];
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
  __OU_INDEX[key] = { ou: _normalizeOU_(obj.ou || ''), lastSeenISO: obj.lastSeenISO || now };
}

function _batchWriteOURows_(shOU, entries) {
  if (!entries || !entries.length) return;
  if (!__OU_ROW_INDEX) __OU_ROW_INDEX = {};
  if (!__OU_INDEX)     __OU_INDEX     = {};
  const now = new Date().toISOString();
  const toUpdate = [];
  const toAppend = [];
  for (const { email, obj } of entries) {
    const key = String(email || '').toLowerCase().trim();
    if (!key) continue;
    const row = [email, _asTextLiteral_(_resolveOU_(email, obj.ou || '')), obj.lastSeenISO || now];
    __OU_INDEX[key] = { ou: _normalizeOU_(obj.ou || ''), lastSeenISO: obj.lastSeenISO || now };
    if (__OU_ROW_INDEX[key]) {
      toUpdate.push({ sheetRow: __OU_ROW_INDEX[key], row });
    } else {
      toAppend.push({ key, row });
    }
  }
  for (const { sheetRow, row } of toUpdate) {
    shOU.getRange(sheetRow, 1, 1, OU_HEADERS.length).setValues([row]);
  }
  if (toAppend.length) {
    const firstNewRow = shOU.getLastRow() + 1;
    shOU.getRange(firstNewRow, 1, toAppend.length, OU_HEADERS.length).setValues(toAppend.map(e => e.row));
    toAppend.forEach((e, i) => { __OU_ROW_INDEX[e.key] = firstNewRow + i; });
  }
}

function _bulkLoadAllOUs_(shOU) {
  const map = __getOUMap();
  const now = new Date().toISOString();
  let token;
  const staleUsers = [];

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
      if (_isFreshOU_(map[email])) continue;
      staleUsers.push({ email, ou: u.orgUnitPath || '/' });
    }

    token = resp && resp.nextPageToken;
  } while (token);

  if (!staleUsers.length) return 0;

  for (const { email, ou } of staleUsers) {
    map[email] = { ou, lastSeenISO: now };
    if (!__OU_INDEX) __OU_INDEX = {};
    __OU_INDEX[email] = { ou: _normalizeOU_(ou), lastSeenISO: now };
  }

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

function _isMonitoredOU_(ou) {
  if (!CONFIG.MONITOR_OUS || !String(CONFIG.MONITOR_OUS).trim()) return true;
  const targets = String(CONFIG.MONITOR_OUS).split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  if (!targets.length) return true;
  const resolved = String(ou || '').toLowerCase();
  return targets.some(t => resolved === t || resolved.startsWith(t + '/'));
}

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
  return { ous: Array.from(set).sort(), current: CONFIG.MONITOR_OUS || '' };
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
