/* global AdminReports, AdminDirectory */
/**
 * Sync.gs — Core sync engine: scheduledSync, _syncCore, fetch, trim, backfill, diagnostics.
 */

function scheduledSync() {
  _applyRuntimeConfig_();
  _syncCore('scheduledSync');
}

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

    const props = PropertiesService.getScriptProperties();
    const now = new Date();
    const endU = new Date(now.getTime() - CONFIG.API_LAG_MINUTES*60000);
    const lastRunISO = props.getProperty('lastRunISO');
    const startU = lastRunISO
      ? new Date(new Date(lastRunISO).getTime() - CONFIG.OVERLAP_MINUTES*60000)
      : new Date(endU.getTime() - CONFIG.LOOKBACK_MINUTES_ON_FIRST_RUN*60000);

    const {rows, count, uniqueIps, uniqueEmails} = _fetchLoginRows_(startU, endU, triggerName);
    eventsParsed = count;

    const geoMap = _loadGeoMap_(shGeo);
    const ipsToEnrich = [];
    uniqueIps.forEach(ip => { if (ip && !_isFreshGeo_(geoMap[ip])) ipsToEnrich.push(ip); });
    if (ipsToEnrich.length) {
      const batchResults = _geolocateBatch_(ipsToEnrich);
      const geoEntries = Object.entries(batchResults);
      geoEntries.forEach(([ip, g]) => { geoMap[ip] = g; });
      _batchWriteGeoRows_(shGeo, batchResults);
    }

    _retryFailedGeoLookups_(shGeo);

    if (CONFIG.BULK_OU_LOAD) {
      _bulkLoadAllOUs_(shOU);
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

    const campusIPs = CONFIG.CAMPUS_IP_FILTER
      ? new Set(String(CONFIG.CAMPUS_IP_FILTER).split(',').map(s => s.trim()).filter(Boolean))
      : new Set();

    const filteredRows = rows.filter(r => {
      if (campusIPs.size && r.ip && campusIPs.has(r.ip)) return false;
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

    if (out.length) {
      const existingKeys = _loadKeyIndex_();
      const newRows = out.filter(r => {
        const k = r[MAIN_HEADERS.indexOf('Event Key')];
        return k && !existingKeys.has(k);
      });
      if (newRows.length) {
        shMain.getRange(shMain.getLastRow() + 1, 1, newRows.length, MAIN_HEADERS.length).setValues(newRows);
        _appendToKeyIndex_(newRows.map(r => r[MAIN_HEADERS.indexOf('Event Key')]));
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

    if (CONFIG.TRIM_AFTER_SYNC) trimMainRolling();

    const isFirstRun = !lastRunISO;
    if (!isFirstRun || rowsAppended > 0) {
      props.setProperty('lastRunISO', endU.toISOString());
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

function trimMainRolling() {
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shArchive = ss.getSheetByName(CONFIG.ARCHIVE);
  const rows = _getRows(shMain);
  if (!rows.length) return;
  const cutoff = new Date(Date.now() - CONFIG.KEEP_DAYS * 24 * 3600000);
  const oldRows = [];
  const keepRows = [];
  for (let i = 0; i < rows.length; i++) {
    const ts = new Date(rows[i][0]);
    if (isNaN(ts)) { keepRows.push(rows[i]); continue; }
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

function _fetchLoginRows_(startU, endU, triggerName) {
  triggerName = triggerName || 'unknown';
  var rows = [];
  var uniqueIps = new Set();
  var uniqueEmails = new Set();

  if (!(startU instanceof Date) || !(endU instanceof Date) || startU >= endU) {
    return {rows: [], count: 0, uniqueIps, uniqueEmails};
  }

  var sliceStart = new Date(startU);
  var sliceEnd   = new Date(endU);

  function fetchWindow(wStart, wEnd) {
    let token, pageCount = 0, gotAny = false;
    do {
      const params = { startTime: wStart.toISOString(), endTime: wEnd.toISOString(), maxResults: 500 };
      if (token) params.pageToken = token;
      const resp = _reportsListSafe_('all', 'login', params);
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
              if (evName === 'account_disabled_password_leak' && email) {
                _maybeAlertPasswordLeak_(triggerName, email, ts);
              }
            }
          }
        }
      }
      token = resp && resp.nextPageToken;
      if (token) _sleep(150);
    } while (token);
    return gotAny;
  }

  try {
    fetchWindow(sliceStart, sliceEnd);
  } catch (e) {
    var msg = (e && e.message) ? e.message : String(e);
    if (/Empty response/i.test(msg)) {
      var cursor = new Date(sliceStart);
      while (cursor < sliceEnd) {
        var next = new Date(Math.min(cursor.getTime() + 3600000, sliceEnd.getTime()));
        try {
          fetchWindow(cursor, next);
        } catch (e2) {
          _logDiagnostics('_fetchLoginRows_/hour-skip', cursor, next, 0, 0,
            'Skipped 1h due to: ' + ((e2 && e2.message) ? e2.message : String(e2)));
        }
        cursor = next;
      }
    } else {
      throw e;
    }
  }

  return {rows: rows, count: rows.length, uniqueIps: uniqueIps, uniqueEmails: uniqueEmails};
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

function backfillFourDays() { backfillDays(4, 6); }

function backfillDays(days, chunkHours) {
  _applyRuntimeConfig_();
  const __ouMap = __getOUMap();
  days = Number(days) || 4;
  chunkHours = Number(chunkHours) || 6;

  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shGeo  = ss.getSheetByName(CONFIG.GEOCACHE);
  const shOU   = ss.getSheetByName(CONFIG.OU_CACHE);

  const endAll = new Date();
  const startAll = new Date(endAll.getTime() - days*24*3600000);

  const geoMap = _loadGeoMap_(shGeo);
  const ouMap  = _loadOUMap_(shOU);

  let cursor = new Date(startAll);
  let totalParsed = 0, totalAppended = 0, batches = 0;

  const campusIPs_bf = CONFIG.CAMPUS_IP_FILTER
    ? new Set(String(CONFIG.CAMPUS_IP_FILTER).split(',').map(s => s.trim()).filter(Boolean))
    : new Set();

  while (cursor < endAll) {
    const sliceStart = new Date(cursor);
    const sliceEnd   = new Date(Math.min(cursor.getTime() + chunkHours*3600000, endAll.getTime()));

    const {rows, count, uniqueIps, uniqueEmails} = _fetchLoginRows_(sliceStart, sliceEnd, 'backfillDays');
    totalParsed += count;

    const ipsToEnrich = [];
    uniqueIps.forEach(ip => { if (ip && !_isFreshGeo_(geoMap[ip])) ipsToEnrich.push(ip); });
    if (ipsToEnrich.length) {
      const batchResults = _geolocateBatch_(ipsToEnrich);
      Object.entries(batchResults).forEach(([ip, g]) => { geoMap[ip] = g; });
      _batchWriteGeoRows_(shGeo, batchResults);
    }

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

    if (rows.length) {
      const out = rows.filter(r => !(campusIPs_bf.size && r.ip && campusIPs_bf.has(r.ip))).map(r => {
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
      shMain.getRange(shMain.getLastRow()+1, 1, out.length, MAIN_HEADERS.length).setValues(out);
      totalAppended += out.length;
      batches++;
    }

    cursor = sliceEnd;
    Utilities.sleep(200);
  }

  _dedupeSheetByKey(shMain, MAIN_HEADERS, MAIN_HEADERS.indexOf('Event Key'));
  _refreshActiveNow_();
  _refreshSuspicious_('backfillDays');
  trimMainRolling();

  _logDiagnostics('backfillDays', startAll, endAll, totalParsed, totalAppended,
    'days=' + days + ', chunkHours=' + chunkHours + ', batches=' + batches);
}

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
  let ipCount = 0, userCount = 0;
  for (const r of rows) {
    const ip = r[ipIndex];
    const email = r[emailIndex];
    if (ip && !geoIPs.has(ip) && ipCount < CONFIG.CACHE_WARMUP_BATCH_IP) {
      const g = _geolocate(ip);
      if (g) { geoIPs.add(ip); _upsertGeoRow_(geo, ip, g); }
      ipCount++;
    }
    if (email && !ouUsers.has(email) && userCount < CONFIG.CACHE_WARMUP_BATCH_USER) {
      const ouPath = _getOUForEmail_(email);
      if (ouPath) {
        const obj = {ou:ouPath, lastSeenISO:new Date().toISOString()};
        _upsertOURow_(ou, email, obj);
      }
      userCount++;
    }
    if (ipCount >= CONFIG.CACHE_WARMUP_BATCH_IP && userCount >= CONFIG.CACHE_WARMUP_BATCH_USER) break;
  }
}

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

function trimDiagnosticsSheet() {
  const sh = SpreadsheetApp.getActive().getSheetByName(CONFIG.DIAG);
  if (!sh) return;
  const lastRow = sh.getLastRow();
  if (lastRow < 2) return;
  const keepDays = Number(PropertiesService.getScriptProperties().getProperty('KEEP_DIAG_DAYS') || 7);
  const cutoff = new Date(Date.now() - keepDays * 24 * 60 * 60 * 1000);
  const data = sh.getRange(2, 1, lastRow - 1, 2).getValues();
  var deleteRows = [];
  for (var i = data.length - 1; i >= 0; i--) {
    const rowDate = new Date(data[i][1]);
    if (isNaN(rowDate.getTime())) continue;
    if (rowDate < cutoff) deleteRows.push(i + 2);
  }
  deleteRows.sort(function(a, b) { return b - a; });
  var i = 0;
  while (i < deleteRows.length) {
    var start = deleteRows[i];
    var count = 1;
    while (i + count < deleteRows.length && deleteRows[i + count] === start - count) count++;
    sh.deleteRows(start - count + 1, count);
    i += count;
  }
  const removed = deleteRows.length;
  if (removed > 0) {
    _logDiagnostics('trimDiagnostics', new Date(), new Date(), removed, 0,
      'Removed ' + removed + ' rows older than ' + keepDays + ' days. Cutoff: ' + cutoff.toISOString());
  }
  return removed;
}

function trimDiagnosticsSheetMenu() {
  const removed = trimDiagnosticsSheet();
  SpreadsheetApp.getActive().toast(
    'Diagnostics trimmed — ' + (removed || 0) + ' old rows removed.',
    'Workspace Watchdog', 5
  );
}
