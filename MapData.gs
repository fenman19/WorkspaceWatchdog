/* global AdminReports, AdminDirectory */
/**
 * MapData.gs — Live map data feeds: getLiveMapData, Active Now, Suspicious,
 *               map notifications, OU list, sync time, active count.
 */

function getLiveMapData(opts) {
  _applyRuntimeConfig_();
  opts = opts || {};
  const maxRows   = Number(opts.maxRows)  || 2000;
  const eventType = opts.eventType        || 'all';
  const outsideUS = opts.outsideUS        === true;
  const ouFilter  = opts.ou               || '';
  const hoursBack = Number(opts.hoursBack)|| 0;

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
      email, evName, ip, city, region, country, isp,
      lat:     Number(parts[0]),
      lon:     Number(parts[1]),
      ou,
      outside: !!outsideUSFlag
    });
  }

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

  let riskScores = {};
  try { riskScores = getUserRiskScores(); } catch(e) {}

  return { rows: out, total: data.length, chartDays, chartHours, riskScores };
}

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
      lat: Number(parts[0]), lon: Number(parts[1]),
      outside: !!outsideUS
    });
  }

  return { rows: out, total: out.length };
}

function getSuspiciousMapData() {
  _applyRuntimeConfig_();
  const ss     = SpreadsheetApp.getActive();
  const shSusp = ss.getSheetByName(CONFIG.SUSPICIOUS);
  if (!shSusp || shSusp.getLastRow() <= 1) return { rows: [], arcs: [] };

  const shMain = ss.getSheetByName(CONFIG.MAIN);
  const keyToLL = {};
  if (shMain && shMain.getLastRow() > 1) {
    const mainData = shMain.getRange(2, 1, shMain.getLastRow() - 1, 11).getValues();
    for (const m of mainData) {
      const key   = String(m[9]  || '');
      const latlng= String(m[10] || '');
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

    let resolvedLL = fromLL;
    if (!resolvedLL || !resolvedLL.includes(',')) {
      resolvedLL = keyToLL[keyA] || keyToLL[keyB] || '';
    }

    rows.push({ ts, email, reason, details,
                fromCity, fromReg, fromCo, fromLL: resolvedLL,
                toCity, toReg, toCo, toLL, dist, speed, severity });

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

function getActiveNowCount() {
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.ACTIVE);
  if (!sh || sh.getLastRow() <= 1) return 0;
  return sh.getLastRow() - 1;
}

function getLastSyncTime() {
  const p = PropertiesService.getScriptProperties();
  return p.getProperty('lastSyncWallTime') || p.getProperty('lastRunISO') || '';
}

function getMapOUList() {
  _applyRuntimeConfig_();
  const res = getMonitorableOUs();
  return res.ous || [];
}

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

  const lastCheck  = props.getProperty(UPDATER.PROP_LAST_CHECK);
  const sixHoursMs = 6 * 60 * 60 * 1000;
  const needsCheck = !lastCheck || (Date.now() - new Date(lastCheck).getTime()) > sixHoursMs;

  if (needsCheck) {
    try {
      const resp = UrlFetchApp.fetch(UPDATER.VERSION_URL, { muteHttpExceptions: true, deadline: 5 });
      if (resp.getResponseCode() === 200) {
        const remote = JSON.parse(resp.getContentText());
        props.setProperty(UPDATER.PROP_LAST_CHECK, new Date().toISOString());
        props.setProperty('WW_LATEST_VERSION', remote.version);
        result.latestVersion    = remote.version;
        result.updateAvailable  = _versionCompare_(result.installedVersion, remote.version) < 0;
      }
    } catch(e) { /* silent — don't block map load */ }
  } else {
    const cached = props.getProperty('WW_LATEST_VERSION');
    if (cached) {
      result.latestVersion   = cached;
      result.updateAvailable = _versionCompare_(result.installedVersion, cached) < 0;
    }
  }

  const expiryStr = props.getProperty('WW_LICENSE_EXPIRY');
  if (expiryStr) {
    const expiry   = new Date(expiryStr);
    const daysLeft = Math.ceil((expiry - Date.now()) / (1000 * 60 * 60 * 24));
    result.licenseDaysLeft = daysLeft;
    if (daysLeft <= 0)       result.licenseExpired  = true;
    else if (daysLeft <= 30) result.licenseExpiring = true;
  }

  return result;
}
