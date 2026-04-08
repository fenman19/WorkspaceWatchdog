/* global AdminReports, AdminDirectory */
/**
 * Detection.gs — Active Now refresh, Suspicious event detection (impossible travel,
 *                login bursts, outside US), and user risk scoring.
 */

function migrateSuspiciousSheet() {
  const ss     = SpreadsheetApp.getActive();
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);
  if (!shSusp) return;
  const lastCol = shSusp.getLastColumn();
  const expectedCols = SUSP_HEADERS.length;
  if (lastCol >= expectedCols) {
    SpreadsheetApp.getActive().toast('Suspicious sheet already up to date.', 'Watchdog', 3);
    return;
  }
  shSusp.getRange(1, expectedCols).setValue('Alerted');
  const lastRow = shSusp.getLastRow();
  if (lastRow > 1) shSusp.getRange(2, expectedCols, lastRow - 1, 1).setValue('');
  SpreadsheetApp.getActive().toast(
    'Added Alerted column to Suspicious sheet. ' + (lastRow - 1) + ' rows updated.',
    'Workspace Watchdog', 5);
}

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
    ts: new Date(r[0]), email: r[1], name: r[2], row: r
  })).filter(x => x.email);

  const windowObjs = allObjs.filter(x => x.ts >= cutoff);
  const byUser = {};

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
      _fmtCT(u.first), _fmtCT(u.last),
      sourcesList, minutes, u.count,
      lastIp, city, region, country, isp, latlng, geoSrc,
      lastNoTZ, hourBucket, outsideUS, hasGeo
    ];
  });

  _clearBody(shActive); _setHeaders(shActive, ACTIVE_HEADERS);
  if (out.length) shActive.getRange(2,1,out.length,ACTIVE_HEADERS.length).setValues(out);
}

function _refreshSuspicious_(triggerName) {
  const ss = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);

  if (shSusp && shSusp.getLastRow() >= 1 && shSusp.getLastColumn() < SUSP_HEADERS.length) {
    shSusp.getRange(1, SUSP_HEADERS.length).setValue('Alerted');
    if (shSusp.getLastRow() > 1) {
      shSusp.getRange(2, SUSP_HEADERS.length, shSusp.getLastRow() - 1, 1).setValue('');
    }
  }

  const alertedKeys = new Set();
  if (shSusp && shSusp.getLastRow() > 1) {
    const numCols = Math.min(shSusp.getLastColumn(), SUSP_HEADERS.length);
    const existing = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, numCols).getValues();
    existing.forEach(r => {
      if (r.length >= 20 && String(r[19]) === 'Yes') {
        alertedKeys.add(String(r[14]) + '_' + String(r[15] || ''));
      }
    });
  }

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
    ts: new Date(r[0]), email: r[1], name: r[2], ip: r[3],
    city: r[4], region: r[5], country: r[6], isp: r[7],
    key: r[9], latlng: r[10] || ''
  })).filter(r => r.email);

  const byUser = {};
  rows.forEach(r => { if (!byUser[r.email]) byUser[r.email] = []; byUser[r.email].push(r); });
  Object.keys(byUser).forEach(k => byUser[k].sort((a,b)=>a.ts-b.ts));

  const out = [];

  function _suspTail_(dateObj, reason) {
    const suspNoTZ = _fmtCT_no_tz_(dateObj);
    const hb = _hourBucketNoTZ_(dateObj);
    const severity = (reason === 'Impossible Travel') ? 3 : (reason === 'Login Burst') ? 2 : (reason === 'Outside US') ? 1 : 0;
    return [suspNoTZ, hb, severity];
  }

  // Outside US
  rows.forEach(r => {
    if (r.country && r.country !== 'US') {
      if (_isWhitelisted_(r.email, r.ip)) return;
      const tail = _suspTail_(r.ts, 'Outside US');
      const ouAlertKey = String(r.key) + '_';
      const ouAlerted  = _isAlertedPermanently_(ouAlertKey) ? 'Yes' : '';
      out.push([
        _fmtCT(r.ts), r.email, 'Outside US', 'Country=' + r.country,
        '', '', '', '', '', '', '', '', '', '', r.key, '',
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
        if (_isWhitelisted_(email, null)) { i = j - 1; continue; }
        const last = evs[j-1];
        const tail = _suspTail_(last.ts, 'Login Burst');
        const burstAlertKey = String(evs[i].key) + '_' + String(last.key || '');
        const burstAlerted  = _isAlertedPermanently_(burstAlertKey) ? 'Yes' : '';
        out.push([
          _fmtCT(last.ts), email, 'Login Burst', c + ' events <= ' + CONFIG.BURST_WINDOW_MIN + ' min',
          '', '', '', '', '', '', '', '', '', '', evs[i].key, last.key,
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

  // Impossible Travel
  Object.keys(byUser).forEach(email => {
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
          if (_isWhitelisted_(email, a.ip) || _isWhitelisted_(email, b.ip)) continue;
          if (a.ip && b.ip && a.ip === b.ip) continue;
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

  const combined = out.concat(retained);
  _clearBody(shSusp); _setHeaders(shSusp, SUSP_HEADERS);
  if (combined.length) shSusp.getRange(2,1,combined.length,SUSP_HEADERS.length).setValues(combined);
  _dedupeSheetByKey(shSusp, SUSP_HEADERS, SUSP_HEADERS.indexOf('Timestamp (CT)'));
  _dedupeByComposite_(shSusp, [1,2,3,16,17]);
}

// ===== Risk Scoring ===========================================================

function getUserRiskScores() {
  _applyRuntimeConfig_();
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const scores  = {};
  const cutoff  = new Date(Date.now() - 7 * 24 * 3600000);

  function ensure(email) { if (!scores[email]) scores[email] = 0; }

  if (shMain && shMain.getLastRow() > 1) {
    const rows = shMain.getRange(2, 1, shMain.getLastRow() - 1, 16).getValues();
    for (const r of rows) {
      const ts = r[0], email = String(r[1] || '').toLowerCase();
      const evName = String(r[2] || ''), outside = r[15];
      if (!email || new Date(ts) < cutoff) continue;
      ensure(email);
      if (evName === 'login_failure') scores[email] += 5;
      if (outside === true)           scores[email] += 10;
      const hourCT = Number(Utilities.formatDate(new Date(ts), CONFIG.TZ, 'H'));
      if (hourCT >= 0 && hourCT < 5)  scores[email] += 3;
    }
  }

  if (shSusp && shSusp.getLastRow() > 1) {
    const rows = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, 3).getValues();
    for (const r of rows) {
      const ts = r[0], email = String(r[1] || '').toLowerCase(), reason = String(r[2] || '');
      if (!email || new Date(ts) < cutoff) continue;
      ensure(email);
      if (reason === 'Impossible Travel') scores[email] += 20;
      if (reason === 'Login Burst')       scores[email] += 15;
    }
  }

  Object.keys(scores).forEach(k => { scores[k] = Math.min(100, scores[k]); });
  return scores;
}

function getUserRiskScore(email) {
  if (!email) return 0;
  const scores = getUserRiskScores();
  return scores[String(email).toLowerCase()] || 0;
}

function getUserRiskTrend(email) {
  if (!email) return [];
  email = String(email).toLowerCase();
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shArch  = ss.getSheetByName(CONFIG.ARCHIVE);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const cutoff28 = new Date(Date.now() - 28 * 24 * 3600000);

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
    allRows.forEach(function(r) {
      var ts = new Date(r[0]);
      if (ts < wk.start || ts >= wk.end) return;
      var evName  = String(r[2] || ''), outside = r[15];
      if (evName === 'login_failure') score += 5;
      if (outside === true)           score += 10;
      var hourCT = Number(Utilities.formatDate(ts, CONFIG.TZ, 'H'));
      if (hourCT >= 0 && hourCT < 5) score += 3;
    });
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

function getTopRiskUsers(n) {
  n = n || 5;
  const scores = getUserRiskScores();
  return Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([email, score]) => ({ email, score }));
}
