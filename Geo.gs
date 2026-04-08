/* global AdminReports, AdminDirectory */
/**
 * Geo.gs — Geolocation system: batch lookup, GeoCache management, provider fallback,
 *          backfill helpers, and IP reputation (AbuseIPDB).
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

function _geolocate(ip) {
  if (!ip) return null;
  const r2 = _geo_ipinfo(ip);      if (r2) return r2;
  const r1 = _geo_ipapi(ip);       if (r1) return r1;
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
    const u = 'https://freeipapi.com/api/json/' + encodeURIComponent(ip);
    const res = UrlFetchApp.fetch(u, {muteHttpExceptions:true, timeout:10000});
    if (res.getResponseCode() !== 200) return null;
    const j = JSON.parse(res.getContentText()||'{}');
    if (!_isCoord(j.latitude) || !_isCoord(j.longitude)) return null;
    return {city:j.cityName||'', region:j.regionName||'', country:j.countryCode||j.countryName||'', isp:_cleanIsp_(j.asnOrganization||''), lat:+j.latitude, lon:+j.longitude, source:'freeipapi.com', lastSeenISO:new Date().toISOString()};
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
      city: r[1], region: r[2], country: r[3], isp: r[4] || '',
      lat: _num(r[5]), lon: _num(r[6]), source: r[7], lastSeenISO: r[8]
    };
    rowIdx[ip] = i + 2;
  });
  __GEO_INDEX = map;
  __GEO_ROW_INDEX = rowIdx;
  return map;
}

function _isFreshGeo_(g) {
  if (!g || !g.lastSeenISO) return false;
  if (g.source === 'failed') return false;
  const ageH = (Date.now() - new Date(g.lastSeenISO).getTime())/3600000;
  return ageH < CONFIG.GEO_TTL_HOURS;
}

function _upsertGeoRow_(shGeo, ip, g) {
  if (!__GEO_ROW_INDEX) __GEO_ROW_INDEX = {};
  const existingRow = __GEO_ROW_INDEX[ip];
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
    city: g.city||'', region: g.region||'', country: g.country||'', isp: g.isp||'',
    lat: _num(g.lat), lon: _num(g.lon), source: g.source||'', lastSeenISO: g.lastSeenISO||now
  };
}

function _retryFailedGeoLookups_(shGeo) {
  if (!shGeo || shGeo.getLastRow() <= 1) return;
  const data = shGeo.getRange(2, 1, shGeo.getLastRow() - 1, GEO_HEADERS.length).getValues();
  const retryIPs = [];
  for (const r of data) {
    if (String(r[7] || '') === 'failed') retryIPs.push(String(r[0] || ''));
  }
  if (!retryIPs.length) return;
  const batch = retryIPs.slice(0, 20);
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

function _batchWriteGeoRows_(shGeo, geoMap) {
  const entries = Object.entries(geoMap);
  if (!entries.length) return;
  if (!__GEO_ROW_INDEX) __GEO_ROW_INDEX = {};
  if (!__GEO_INDEX)     __GEO_INDEX     = {};
  const now = new Date().toISOString();
  const toUpdate = [];
  const toAppend = [];

  for (const [ip, g] of entries) {
    const row = [ip, g.city||'', g.region||'', g.country||'', g.isp||'', _num(g.lat), _num(g.lon), g.source||'', g.lastSeenISO||now];
    __GEO_INDEX[ip] = {
      city: g.city||'', region: g.region||'', country: g.country||'', isp: g.isp||'',
      lat: _num(g.lat), lon: _num(g.lon), source: g.source||'', lastSeenISO: g.lastSeenISO||now
    };
    if (__GEO_ROW_INDEX[ip]) {
      toUpdate.push({ sheetRow: __GEO_ROW_INDEX[ip], row });
    } else {
      toAppend.push({ ip, row });
    }
  }

  for (const { sheetRow, row } of toUpdate) {
    shGeo.getRange(sheetRow, 1, 1, GEO_HEADERS.length).setValues([row]);
  }

  if (toAppend.length) {
    const firstNewRow = shGeo.getLastRow() + 1;
    shGeo.getRange(firstNewRow, 1, toAppend.length, GEO_HEADERS.length).setValues(toAppend.map(e => e.row));
    toAppend.forEach((e, i) => { __GEO_ROW_INDEX[e.ip] = firstNewRow + i; });
  }
}

function fillBlankGeoInMain() {
  _applyRuntimeConfig_();
  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shGeo  = ss.getSheetByName(CONFIG.GEOCACHE);
  if (!shMain || shMain.getLastRow() <= 1) {
    SpreadsheetApp.getActive().toast('Main sheet is empty.', 'Workspace Watchdog', 3);
    return;
  }
  const geoMap = _loadGeoMap_(shGeo);
  const lastRow = shMain.getLastRow();
  const data    = shMain.getRange(2, 1, lastRow - 1, MAIN_HEADERS.length).getValues();

  const COL_IP=3, COL_CITY=4, COL_REGION=5, COL_COUNTRY=6, COL_ISP=7,
        COL_LATLNG=10, COL_GEOSRC=11, COL_OUTSIDE=15, COL_HASGEO=16;

  let updated = 0;
  const updates = [];

  data.forEach((r, i) => {
    const ip  = String(r[COL_IP] || '').trim();
    const city = String(r[COL_CITY] || '').trim();
    const isp  = String(r[COL_ISP]  || '').trim();
    const isBadGeo = city === 'failed' || city === 'error' || city === 'unknown';
    if (!ip || (city && isp && !isBadGeo)) return;
    let g = geoMap[ip];
    if (!g || g.source === 'failed' || !g.city) {
      try { g = _geolocate(ip); } catch(e) { g = null; }
    }
    if (!g || !g.city) return;
    const latlng   = (isFinite(g.lat) && isFinite(g.lon)) ? g.lat + ',' + g.lon : '';
    const outsideUS = g.country && g.country !== 'US';
    updates.push({ row: i + 2, city: g.city||'', region: g.region||'', country: g.country||'',
                   isp: g.isp||'', latlng, geosrc: g.source||'', outsideUS, hasGeo: !!latlng });
  });

  if (!updates.length) {
    SpreadsheetApp.getActive().toast('No blank geo rows found in Main sheet.', 'Workspace Watchdog', 4);
    return;
  }

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

// ===== IP Reputation (AbuseIPDB) ==============================================

function checkIPReputation(ip) {
  if (!CONFIG.IP_REP_ENABLED) return null;
  if (!ip) return null;
  const key = PropertiesService.getScriptProperties().getProperty('ABUSEIPDB_KEY');
  if (!key) return null;
  const cacheKey = 'IP_REP:' + ip;
  const cached   = PropertiesService.getScriptProperties().getProperty(cacheKey);
  if (cached) {
    try {
      const parsed = JSON.parse(cached);
      if (parsed._ts && (Date.now() - parsed._ts) < CONFIG.IP_REP_CACHE_DAYS * 86400000) return parsed;
    } catch (_) {}
  }
  try {
    const url  = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' +
                 encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';
    const resp = UrlFetchApp.fetch(url, {
      headers: { 'Key': key, 'Accept': 'application/json' }, muteHttpExceptions: true
    });
    if (resp.getResponseCode() !== 200) return null;
    const j    = JSON.parse(resp.getContentText() || '{}');
    const d    = (j && j.data) ? j.data : null;
    if (!d) return null;
    const result = {
      score: d.abuseConfidenceScore || 0,
      isVpn: !!(d.usageType && /vpn|proxy|hosting/i.test(d.usageType)),
      isTor: !!d.isTor,
      usageType: d.usageType || '',
      domain: d.domain || '',
      country: d.countryCode || '',
      reports: d.totalReports || 0,
      flagged: (d.abuseConfidenceScore || 0) >= CONFIG.IP_REP_MIN_SCORE,
      _ts: Date.now()
    };
    PropertiesService.getScriptProperties().setProperty(cacheKey, JSON.stringify(result));
    return result;
  } catch (e) { return null; }
}

function checkIPReputationBatch(ips) {
  const results = {};
  if (!CONFIG.IP_REP_ENABLED || !ips || !ips.length) return results;
  for (const ip of ips) {
    const r = checkIPReputation(ip);
    if (r) results[ip] = r;
    _sleep(100);
  }
  return results;
}

function getIPReputation(ip) {
  _applyRuntimeConfig_();
  return checkIPReputation(ip);
}

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
