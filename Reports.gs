/* global AdminReports, AdminDirectory */
/**
 * Reports.gs — Daily digest, weekly email report, on-demand security reports,
 *               and all associated HTML email builders.
 */

// ===== Daily Digest ===========================================================

function dailyDigest() {
  _applyRuntimeConfig_();
  const chatEnabled  = CONFIG.DIGEST_ENABLED;
  const emailEnabled = CONFIG.DIGEST_EMAIL_ENABLED;
  if (!chatEnabled && !emailEnabled) return;
  const hourCT = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'H'));
  if (hourCT !== CONFIG.DIGEST_HOUR) return;
  const p        = PropertiesService.getScriptProperties();
  const dedupKey = 'ww_chat_digest_' + Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd');
  if (p.getProperty(dedupKey)) return;
  p.setProperty(dedupKey, new Date().toISOString());
  try {
    const data = _buildDigestData_();
    if (chatEnabled) {
      const url = p.getProperty('CHAT_WEBHOOK_URL');
      if (url) sendChatAlert_(_buildDigestMessage_());
    }
    if (emailEnabled) _sendDigestEmail_(data);
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
    SpreadsheetApp.getUi().alert('No webhook configured.', 'Add CHAT_WEBHOOK_URL to Script Properties first.', SpreadsheetApp.getUi().ButtonSet.OK);
    return;
  }
  try {
    const data = _buildDigestData_();
    sendChatAlert_(_buildDigestMessage_());
    _sendDigestEmail_(data);
    SpreadsheetApp.getActive().toast('Digest sent (Chat + email).', 'Workspace Watchdog', 5);
  } catch (e) {
    SpreadsheetApp.getUi().alert('Digest Error', e && e.message ? e.message : String(e), SpreadsheetApp.getUi().ButtonSet.OK);
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
  recent.filter(r => r[2] === 'login_failure').forEach(r => { failMap[r[1]] = (failMap[r[1]] || 0) + 1; });
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

  const p = PropertiesService.getScriptProperties();
  let yesterday = null;
  try { const snap = p.getProperty('DIGEST_SNAPSHOT'); if (snap) yesterday = JSON.parse(snap); } catch(e) {}
  try {
    p.setProperty('DIGEST_SNAPSHOT', JSON.stringify({
      date: Utilities.formatDate(new Date(), CONFIG.TZ, 'yyyy-MM-dd'),
      totalEvents, successCount, failCount, outsideCount, failRate: parseFloat(failRate)
    }));
  } catch(e) {}

  let comparison = null;
  if (yesterday) {
    const yesterdayDate = Utilities.formatDate(new Date(Date.now() - 24*3600000), CONFIG.TZ, 'yyyy-MM-dd');
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
    d.suspRecent.slice(0, 5).forEach(r => { msg += String(r[0]).slice(0,16) + ' | ' + r[1] + ' | ' + r[2] + '\n'; });
  }
  if (d.topFails.length) {
    msg += '\n*Top Failed Login Accounts*\n';
    d.topFails.forEach(([email, n]) => { msg += email + ': ' + n + ' failed attempt' + (n !== 1 ? 's' : '') + '\n'; });
  }
  msg += '\n*Active Now*\n';
  msg += 'Active users: ' + d.activeCount + '\n';
  if (d.activeOutside > 0) msg += 'Active outside US: ' + d.activeOutside + '\n';
  if (d.topRisk.length) {
    msg += '\n*Top Risk Users (Last 7 Days)*\n';
    d.topRisk.forEach(u => { const bar = u.score >= 50 ? 'HIGH' : u.score >= 20 ? 'MED' : 'LOW'; msg += u.email + ': ' + u.score + '/100 [' + bar + ']\n'; });
  }
  if (d.risingRisk && d.risingRisk.length) {
    msg += '\n*Rising Risk (Up 15+ pts This Week)*\n';
    d.risingRisk.forEach(u => { msg += u.email + ': ' + u.prev + ' -> ' + u.score + ' (+' + u.diff + ')\n'; });
  }
  return msg;
}

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
      htmlBody: html, name: 'Workspace Watchdog'
    });
  } catch(e) {
    _logDiagnostics('digestEmail/error', new Date(), new Date(), 0, 0,
      'Email digest failed: ' + (e && e.message ? e.message : String(e)));
  }
}

// ===== Weekly Report ==========================================================

function weeklyReport() {
  _applyRuntimeConfig_();
  if (!CONFIG.WEEKLY_REPORT_ENABLED) return;
  if (!CONFIG.DIGEST_EMAIL_ENABLED) return;
  const dayOfWeek = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'u'));
  if (dayOfWeek !== 1) return;
  const hourCT = Number(Utilities.formatDate(new Date(), CONFIG.TZ, 'H'));
  if (hourCT !== CONFIG.DIGEST_HOUR) return;
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
    SpreadsheetApp.getUi().alert('Weekly Report Error', e && e.message ? e.message : String(e), SpreadsheetApp.getUi().ButtonSet.OK);
  }
}

function _buildWeeklyData_() {
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shArch  = ss.getSheetByName(CONFIG.ARCHIVE);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const now      = new Date();
  const cutoff7d = new Date(now.getTime() - 7 * 24 * 3600000);
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
  const byDay = {};
  allRows.forEach(r => {
    const day = Utilities.formatDate(new Date(r[0]), CONFIG.TZ, 'EEE M/d');
    if (!byDay[day]) byDay[day] = { s: 0, f: 0, o: 0 };
    if (r[2] === 'login_success') byDay[day].s++;
    else if (r[2] === 'login_failure') byDay[day].f++;
    else byDay[day].o++;
  });
  const failMap = {};
  allRows.filter(r => r[2] === 'login_failure').forEach(r => { if (r[1]) failMap[r[1]] = (failMap[r[1]] || 0) + 1; });
  const topFails = Object.entries(failMap).sort((a,b) => b[1]-a[1]).slice(0, 10);
  const activeMap = {};
  allRows.forEach(r => { if (r[1]) activeMap[r[1]] = (activeMap[r[1]] || 0) + 1; });
  const topActive = Object.entries(activeMap).sort((a,b) => b[1]-a[1]).slice(0, 10);
  const suspRows = shSusp && shSusp.getLastRow() > 1
    ? _getRows(shSusp).filter(r => new Date(r[0]) >= cutoff7d) : [];
  const outsideUS = suspRows.filter(r => r[2] === 'Outside US').length;
  const travel    = suspRows.filter(r => r[2] === 'Impossible Travel').length;
  const bursts    = suspRows.filter(r => r[2] === 'Login Burst').length;
  const leakEvents = allRows.filter(r => r[2] === 'account_disabled_password_leak');
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
      try { const h = Number(Utilities.formatDate(new Date(r[0]), CONFIG.TZ, 'H')); if (h >= 0 && h < 5) riskMap[email] += 3; } catch(e) {}
    });
    weekSuspRows.forEach(r => {
      const email = r[1]; if (!email) return;
      if (!riskMap[email]) riskMap[email] = 0;
      if (r[2] === 'Impossible Travel') riskMap[email] += 20;
      if (r[2] === 'Login Burst')       riskMap[email] += 15;
    });
    topRisk = Object.entries(riskMap).filter(e => e[1] > 0).sort((a,b) => b[1]-a[1]).slice(0, 10).map(e => ({ email: e[0], score: Math.min(100, e[1]) }));
  } catch(e) {}
  const weekStart = Utilities.formatDate(cutoff7d, CONFIG.TZ, 'MMM d');
  const weekEnd   = Utilities.formatDate(now, CONFIG.TZ, 'MMM d, yyyy');
  return { weekStart, weekEnd, totalEvents, successCount, failCount, outsideCount, uniqueUsers, failRate, byDay, topFails, topActive, outsideUS, travel, bursts, leakEvents, topRisk, suspRows };
}

function _sendWeeklyEmail_(data) {
  const p          = PropertiesService.getScriptProperties();
  const extraTo    = (p.getProperty('DIGEST_EMAIL_TO') || '').trim();
  const ownerEmail = Session.getEffectiveUser().getEmail();
  var to = ownerEmail;
  if (extraTo) to = to + ',' + extraTo;
  const subject = 'Workspace Watchdog Weekly Report — ' + data.weekStart + ' to ' + data.weekEnd;
  const html    = _buildWeeklyHtml_(data);
  GmailApp.sendEmail(to, subject, 'Please view this email in an HTML-capable client.', {
    htmlBody: html, name: 'Workspace Watchdog'
  });
}

// ===== On-Demand Reports ======================================================

function getReportFilterOptions() {
  _applyRuntimeConfig_();
  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  if (!shMain || shMain.getLastRow() <= 1) return { users: [], ous: [], ips: [] };
  const data = shMain.getRange(2, 1, shMain.getLastRow()-1, 13).getValues();
  const ous  = new Set();
  for (const r of data) { if (r[12]) ous.add(String(r[12]).trim()); }
  return { users: [], ous: Array.from(ous).filter(Boolean).sort().slice(0, 100), ips: [] };
}

function searchReportFilter(type, query) {
  _applyRuntimeConfig_();
  if (!query || query.length < 2) return [];
  const ss     = SpreadsheetApp.getActive();
  const shMain = ss.getSheetByName(CONFIG.MAIN);
  if (!shMain || shMain.getLastRow() <= 1) return [];
  const q    = query.toLowerCase();
  const col  = type === 'user' ? 1 : type === 'ip' ? 3 : 12;
  const data = shMain.getRange(2, 1, shMain.getLastRow()-1, 13).getValues();
  const results = new Set();
  for (const r of data) {
    const val = String(r[col] || '').toLowerCase().trim();
    if (val && val.includes(q)) results.add(val);
    if (results.size >= 50) break;
  }
  return Array.from(results).sort().slice(0, 20);
}

function getReportData(reportType, filterValue, daysBack) {
  _applyRuntimeConfig_();
  const ss      = SpreadsheetApp.getActive();
  const shMain  = ss.getSheetByName(CONFIG.MAIN);
  const shSusp  = ss.getSheetByName(CONFIG.SUSPICIOUS);
  const days    = Number(daysBack) || 7;
  const cutoff  = new Date(Date.now() - days * 24 * 3600000);
  const filter  = String(filterValue || '').trim().toLowerCase();

  const mainRows = [];
  if (shMain && shMain.getLastRow() > 1) {
    const data = shMain.getRange(2, 1, shMain.getLastRow() - 1, 17).getValues();
    for (const r of data) {
      const ts = r[0], email = String(r[1]||'').toLowerCase(), evName = String(r[2]||''),
            ip = String(r[3]||''), city = String(r[4]||''), region = String(r[5]||''),
            country = String(r[6]||''), isp = String(r[7]||''), ouPath = String(r[12]||''),
            outside = r[14] === true || r[14] === 'TRUE' || r[14] === 1, topOU = String(r[16]||'');
      const rowDate = ts instanceof Date ? ts : new Date(ts);
      if (isNaN(rowDate.getTime()) || rowDate < cutoff) continue;
      if (filter) {
        if (reportType === 'user' && email !== filter) continue;
        if (reportType === 'ou'   && !ouPath.toLowerCase().startsWith(filter)) continue;
        if (reportType === 'ip'   && ip !== filter) continue;
      }
      mainRows.push({ ts: _fmtCT_no_tz_(rowDate), email, evName, ip, city, region, country, isp, ouPath, topOU, outside });
    }
  }

  const allowedEmails = reportType === 'ou' ? new Set(mainRows.map(r => r.email)) : null;
  const suspRows = [];
  if (shSusp && shSusp.getLastRow() > 1) {
    const data = shSusp.getRange(2, 1, shSusp.getLastRow() - 1, 12).getValues();
    for (const r of data) {
      const ts = r[0], email = String(r[1]||'').toLowerCase(), reason = String(r[2]||''),
            details = String(r[3]||''), fromCity = String(r[4]||''), toCity = String(r[8]||'');
      const rowDate = ts instanceof Date ? ts : new Date(ts);
      if (isNaN(rowDate.getTime()) || rowDate < cutoff) continue;
      if (filter) {
        if (reportType === 'user' && email !== filter) continue;
        if (reportType === 'ip'   && !details.includes(filter)) continue;
      }
      if (allowedEmails && !allowedEmails.has(email)) continue;
      suspRows.push({ ts: _fmtCT_no_tz_(rowDate), email, reason, details, fromCity, toCity });
    }
  }

  const totalEvents  = mainRows.length;
  const successCount = mainRows.filter(r => r.evName === 'login_success').length;
  const failCount    = mainRows.filter(r => r.evName === 'login_failure').length;
  const outsideFromMain = mainRows.filter(r => r.outside).length;
  const outsideFromSusp = suspRows.filter(r => r.reason === 'Outside US').length;
  const outsideCount = Math.max(outsideFromMain, outsideFromSusp);
  const uniqueUsers  = new Set(mainRows.map(r => r.email)).size;
  const uniqueIPs    = new Set(mainRows.map(r => r.ip)).size;
  const failRate     = (successCount + failCount) > 0
    ? ((failCount / (successCount + failCount)) * 100).toFixed(1) : '0.0';
  const failMap = {};
  mainRows.filter(r => r.evName === 'login_failure').forEach(r => { failMap[r.email] = (failMap[r.email] || 0) + 1; });
  const topFailed = Object.entries(failMap).sort((a,b) => b[1]-a[1]).slice(0, 10);
  const ipMap = {};
  mainRows.forEach(r => { if (r.ip) ipMap[r.ip] = (ipMap[r.ip] || 0) + 1; });
  const topIPs = Object.entries(ipMap).sort((a,b) => b[1]-a[1]).slice(0, 10);
  const ouMap = {};
  mainRows.forEach(r => { if (r.topOU) ouMap[r.topOU] = (ouMap[r.topOU] || 0) + 1; });
  const ouBreakdown = Object.entries(ouMap).sort((a,b) => b[1]-a[1]).slice(0, 15);

  return {
    reportType, filterValue, daysBack: days,
    generatedAt: _fmtCT_no_tz_(new Date()),
    totalEvents, successCount, failCount, failRate, outsideCount, uniqueUsers, uniqueIPs,
    topFailed, topIPs, ouBreakdown, rows: mainRows, suspRows: suspRows
  };
}

function getReportCSV(reportType, filterValue, daysBack) {
  try {
    const data = getReportData(reportType, filterValue, daysBack);
    const lines = [];
    if (reportType === 'suspicious') {
      lines.push(['Timestamp','Email','Reason','Details','From City','To City'].join(','));
      data.suspRows.forEach(function(r) {
        lines.push([r.ts, r.email, r.reason, r.details, r.fromCity, r.toCity]
          .map(function(v) { return '"' + String(v||'').replace(/"/g,'""') + '"'; }).join(','));
      });
    } else {
      lines.push(['Timestamp','Email','Event','IP','ISP','City','Region','Country','OU','Outside US'].join(','));
      data.rows.forEach(function(r) {
        lines.push([r.ts, r.email, r.evName, r.ip, r.isp, r.city, r.region, r.country, r.ouPath, r.outside ? 'Yes' : '']
          .map(function(v) { return '"' + String(v||'').replace(/"/g,'""') + '"'; }).join(','));
      });
    }
    return { ok: true, csv: lines.join('\n'), filename: 'ww_report_' + reportType + '_' + new Date().toISOString().slice(0,10) + '.csv' };
  } catch(e) {
    return { ok: false, message: e.message || String(e) };
  }
}

function sendReportEmail(reportType, filterValue, daysBack, recipientEmail) {
  try {
    const data  = getReportData(reportType, filterValue, daysBack);
    const owner = Session.getEffectiveUser().getEmail();
    const to    = recipientEmail && recipientEmail.trim() ? recipientEmail.trim() : owner;
    const html  = _buildReportHtml_(data);
    const labels = { user: 'User', ou: 'OU', ip: 'IP', suspicious: 'Suspicious', summary: 'Summary' };
    const label  = labels[reportType] || 'Security';
    const filter = filterValue ? ' — ' + filterValue : '';
    const subject = 'Workspace Watchdog ' + label + ' Report' + filter +
                    ' (' + daysBack + 'd) — ' + data.generatedAt.slice(0,10);
    GmailApp.sendEmail(to, subject, '', { htmlBody: html, name: 'Workspace Watchdog' });
    return { ok: true, message: 'Report sent to ' + to };
  } catch(e) {
    return { ok: false, message: e.message || String(e) };
  }
}

// HTML builders are large — kept in full below

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

  var suspRows = '';
  if (d.suspRecent && d.suspRecent.length) {
    d.suspRecent.slice(0, 5).forEach(function(r) {
      var reasonColor = r[2] === 'Login Burst' ? '#ff9800' : r[2] === 'Impossible Travel' ? '#ef5350' : '#ff9800';
      suspRows +=
        '<tr style="border-bottom:1px solid #1e3a5f;">' +
        '<td style="padding:6px 12px;font-size:12px;color:#9aa0a6;">' + String(r[0]).slice(0,16) + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + (r[1]||'') + '</td>' +
        '<td style="padding:6px 12px;font-size:12px;font-weight:600;color:' + reasonColor + ';">' + (r[2]||'') + '</td>' +
        '</tr>';
    });
  }

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

  return [
    '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Workspace Watchdog Daily Digest</title></head>',
    '<body style="margin:0;padding:0;background:#0f1923;font-family:Arial,sans-serif;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1923;padding:24px 0;">',
    '<tr><td align="center">',
    '<table width="620" cellpadding="0" cellspacing="0" style="background:#152232;border-radius:8px;overflow:hidden;max-width:620px;">',
    '<tr><td style="background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 50%,#0a1628 100%);padding:28px 24px 20px;text-align:center;">',
    '<div style="font-family:Arial,sans-serif;font-size:22px;font-weight:700;color:#00c8ff;letter-spacing:2px;text-transform:uppercase;text-shadow:0 0 20px rgba(0,200,255,0.5);">Workspace Watchdog</div></td></tr>',
    '<tr><td style="background:#1a2e45;padding:16px 24px 20px;text-align:center;">',
    '<div style="font-size:20px;font-weight:700;color:#e8eaed;">Daily Security Digest</div>',
    '<div style="font-size:12px;color:#9aa0a6;margin-top:4px;">' + d.date + '</div>',
    '</td></tr>',
    '<tr><td style="padding:20px 24px 0;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Total Events',  d.totalEvents  + (d.comparison ? delta('totalEvents') : ''),   '#8ab4f8'),
    statBox('Successful',    d.successCount + (d.comparison ? delta('successCount') : ''),  '#81c995'),
    statBox('Failed',        d.failCount    + (d.comparison ? delta('failCount') : ''),     failColor),
    statBox('Fail Rate',     d.failRate + '%', d.failRate > 10 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',
    '<tr><td style="padding:12px 24px 0;">',
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Outside US',   d.outsideCount,  outsideColor),
    statBox('Unique Users', d.uniqueUsers,   '#8ab4f8'),
    statBox('Active Now',   d.activeCount,   '#8ab4f8'),
    statBox('Suspicious',   d.outsideUS + d.travel + d.bursts, suspColor),
    '</tr></table></td></tr>',
    '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
    sectionHeader('Suspicious Activity (Last 24 Hours)'),
    dataRow('Outside US Logins',   d.outsideUS,  d.outsideUS > 0  ? '#ff9800' : '#81c995'),
    dataRow('Impossible Travel',   d.travel,     d.travel > 0     ? '#ef5350' : '#81c995'),
    dataRow('Login Bursts',        d.bursts,     d.bursts > 0     ? '#ff9800' : '#81c995'),
    '</table></td></tr>',
    d.suspRecent && d.suspRecent.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHeader('Recent Suspicious Events'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Time</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">User</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Reason</th></tr>',
      suspRows, '</table></td></tr>'
    ].join('') : '',
    d.topFails && d.topFails.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHeader('Top Failed Login Accounts'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Account</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Failures</th></tr>',
      failRows, '</table></td></tr>'
    ].join('') : '',
    d.topRisk && d.topRisk.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHeader('Top Risk Users (Last 7 Days)'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Account</th>',
      '<th style="padding:6px 12px;font-size:11px;color:#8ab4f8;text-align:left;font-weight:600;">Risk Score</th></tr>',
      riskRows, '</table></td></tr>'
    ].join('') : '',
    '<tr><td style="padding:20px 24px;border-top:1px solid #1e3a5f;">',
    '<div style="font-size:11px;color:#5f6368;text-align:center;">',
    'Workspace Watchdog &mdash; Dawson Education Service Cooperative<br>',
    'This digest was generated automatically. Do not reply to this email.',
    '</div></td></tr>',
    '</table></td></tr></table></body></html>'
  ].join('');
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
  var maxFails  = d.topFails.length ? d.topFails[0][1] : 1;
  var failRows = d.topFails.slice(0, 10).map(function(e, i) {
    var clr = e[1] >= 10 ? '#ef5350' : e[1] >= 5 ? '#ff9800' : '#9aa0a6';
    var pct = Math.round((e[1] / maxFails) * 100);
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + (i%2===0?'#152232':'#1a2e45') + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;width:30px;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + e[0] + '</td>' +
      '<td style="padding:7px 12px;font-size:13px;font-weight:700;color:' + clr + ';text-align:right;white-space:nowrap;">' + e[1] + '</td>' +
      '<td style="padding:7px 12px;width:120px;"><div style="background:#1e3a5f;border-radius:3px;height:8px;">' +
      '<div style="background:' + clr + ';width:' + pct + '%;height:8px;border-radius:3px;"></div></div></td>' +
      '</tr>';
  }).join('');
  var activeRows = d.topActive.slice(0, 10).map(function(e, i) {
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + (i%2===0?'#152232':'#1a2e45') + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + e[0] + '</td>' +
      '<td style="padding:7px 12px;font-size:13px;font-weight:700;color:#8ab4f8;text-align:right;">' + e[1] + '</td>' +
      '</tr>';
  }).join('');
  var riskRows = d.topRisk.map(function(u, i) {
    var rc  = u.score >= 50 ? '#ef5350' : u.score >= 20 ? '#ff9800' : '#81c995';
    var rl  = u.score >= 50 ? 'HIGH' : u.score >= 20 ? 'MED' : 'LOW';
    var bg  = i % 2 === 0 ? '#152232' : '#1a2e45';
    var pct = u.score;
    return '<tr style="border-bottom:1px solid #1e3a5f;background:' + bg + ';">' +
      '<td style="padding:7px 12px;font-size:12px;color:#9aa0a6;width:30px;">' + (i+1) + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;color:#e8eaed;word-break:break-all;">' + u.email + '</td>' +
      '<td style="padding:7px 12px;font-size:12px;font-weight:700;color:' + rc + ';text-align:right;white-space:nowrap;">' + u.score + '/100</td>' +
      '<td style="padding:7px 12px;width:120px;"><div style="background:#1e3a5f;border-radius:3px;height:8px;">' +
      '<div style="background:' + rc + ';width:' + pct + '%;height:8px;border-radius:3px;"></div></div>' +
      '<div style="font-size:10px;color:' + rc + ';margin-top:2px;">' + rl + '</div></td></tr>';
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
    '<tr><td style="background:linear-gradient(135deg,#0a1628 0%,#0d1f3c 50%,#0a1628 100%);padding:28px 24px 20px;text-align:center;">',
    '<div style="font-family:Arial,sans-serif;font-size:22px;font-weight:700;color:#00c8ff;letter-spacing:2px;text-transform:uppercase;text-shadow:0 0 20px rgba(0,200,255,0.5);">Workspace Watchdog</div></td></tr>',
    '<tr><td style="background:#1a2e45;padding:16px 24px 20px;text-align:center;">',
    '<div style="font-size:20px;font-weight:700;color:#e8eaed;">Weekly Security Report</div>',
    '<div style="font-size:12px;color:#9aa0a6;margin-top:4px;">' + d.weekStart + ' &mdash; ' + d.weekEnd + '</div>',
    '</td></tr>',
    leakHtml ? '<tr><td><table width="100%" cellpadding="0" cellspacing="0">' + leakHtml + '</table></td></tr>' : '',
    '<tr><td style="padding:20px 24px 8px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Total Events',  d.totalEvents,  '#8ab4f8'),
    statBox('Successful',    d.successCount, '#81c995'),
    statBox('Failed',        d.failCount,    d.failCount > 0 ? '#ef5350' : '#81c995'),
    statBox('Fail Rate',     d.failRate + '%', parseFloat(d.failRate) > 10 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',
    '<tr><td style="padding:0 24px 8px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>',
    statBox('Outside US',   d.outsideCount,  d.outsideCount > 0 ? '#ff9800' : '#81c995'),
    statBox('Unique Users', d.uniqueUsers,   '#8ab4f8'),
    statBox('Susp Events',  d.outsideUS + d.travel + d.bursts, (d.outsideUS+d.travel+d.bursts) > 0 ? '#ff9800' : '#81c995'),
    statBox('Pass Leaks',   d.leakEvents.length, d.leakEvents.length > 0 ? '#ef5350' : '#81c995'),
    '</tr></table></td></tr>',
    '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
    sectionHdr('Suspicious Activity'),
    row2('Outside US Logins',  d.outsideUS,  d.outsideUS  > 0 ? '#ff9800' : '#81c995'),
    row2('Impossible Travel',  d.travel,     d.travel     > 0 ? '#ef5350' : '#81c995'),
    row2('Login Bursts',       d.bursts,     d.bursts     > 0 ? '#ff9800' : '#81c995'),
    '</table></td></tr>',
    '<tr><td><table width="100%" cellpadding="0" cellspacing="0">',
    sectionHdr('Daily Breakdown'),
    '</table>',
    '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
    '<tr style="background:#1e3a5f;"><th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Day</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Total</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#81c995;text-align:right;">Success</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#ef5350;text-align:right;">Failed</th>',
    '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Fail Rate</th></tr>',
    dayRows, '</table></td></tr>',
    d.topFails.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHdr('Top Failed Login Accounts'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Failures</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:120px;">Distribution</th></tr>',
      failRows, '</table></td></tr>'
    ].join('') : '',
    d.topActive.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHdr('Most Active Users'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Logins</th></tr>',
      activeRows, '</table></td></tr>'
    ].join('') : '',
    d.topRisk.length ? [
      '<tr><td><table width="100%" cellpadding="0" cellspacing="0">', sectionHdr('Top Risk Users'), '</table>',
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 24px;width:calc(100% - 48px);">',
      '<tr style="background:#1e3a5f;"><th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:30px;">#</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;">Account</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:right;">Score</th>',
      '<th style="padding:7px 12px;font-size:11px;color:#8ab4f8;text-align:left;width:120px;">Level</th></tr>',
      riskRows, '</table></td></tr>'
    ].join('') : '',
    '<tr><td style="padding:20px 24px;border-top:1px solid #1e3a5f;">',
    '<div style="font-size:11px;color:#5f6368;text-align:center;">',
    'Workspace Watchdog Weekly Report &mdash; Dawson Education Service Cooperative<br>',
    'Generated automatically every Monday morning. Do not reply to this email.',
    '</div></td></tr>',
    '</table></td></tr></table></body></html>'
  ].join('');
}

function _buildReportHtml_(d) {
  const typeLabels = { user: 'User Report', ou: 'OU Report', ip: 'IP Report',
                       suspicious: 'Suspicious Events', summary: 'Summary Report' };
  const title  = typeLabels[d.reportType] || 'Security Report';
  const filter = d.filterValue ? '<br><span style="font-size:13px;color:#9aa0a6;">' + d.filterValue + '</span>' : '';
  function statBox(label, val, color) {
    return '<td style="text-align:center;padding:12px 16px;">' +
      '<div style="font-size:26px;font-weight:700;color:' + color + ';line-height:1;">' + val + '</div>' +
      '<div style="font-size:11px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;">' + label + '</div>' +
      '</td>';
  }
  function sectionHdr(title) {
    return '<tr><td colspan="2" style="padding:16px 24px 6px;">' +
      '<div style="font-size:11px;font-weight:700;color:#8ab4f8;text-transform:uppercase;' +
      'letter-spacing:.08em;border-bottom:1px solid #2a3f5f;padding-bottom:6px;">' + title + '</div></td></tr>';
  }
  var topFailedRows = d.topFailed.map(function(e) {
    var clr = e[1] >= 10 ? '#ef5350' : e[1] >= 5 ? '#ff9800' : '#9aa0a6';
    return '<tr style="border-bottom:1px solid #1e3a5f;">' +
      '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;">' + e[0] + '</td>' +
      '<td style="padding:6px 12px;font-size:12px;font-weight:700;color:' + clr + ';text-align:right;">' + e[1] + '</td></tr>';
  }).join('');
  var suspHtml = d.suspRows.slice(0, 20).map(function(r) {
    var clr = r.reason === 'Impossible Travel' ? '#ff6d00' : r.reason === 'Login Burst' ? '#ffaa00' : '#f44336';
    return '<tr style="border-bottom:1px solid #1e3a5f;">' +
      '<td style="padding:6px 12px;font-size:11px;color:#9aa0a6;white-space:nowrap;">' + r.ts.slice(0,16) + '</td>' +
      '<td style="padding:6px 12px;font-size:12px;color:#e8eaed;">' + r.email + '</td>' +
      '<td style="padding:6px 12px;font-size:12px;font-weight:700;color:' + clr + ';">' + r.reason + '</td>' +
      '<td style="padding:6px 12px;font-size:11px;color:#9aa0a6;">' + r.details.slice(0,60) + '</td></tr>';
  }).join('');
  var recentRows = d.rows.slice(0, 50).map(function(r) {
    var clr = r.evName === 'login_failure' ? '#ef5350' : r.outside ? '#f44336' : '#81c995';
    return '<tr style="border-bottom:1px solid #1e3a5f;">' +
      '<td style="padding:5px 10px;font-size:11px;color:#9aa0a6;white-space:nowrap;">' + r.ts.slice(0,16) + '</td>' +
      '<td style="padding:5px 10px;font-size:11px;color:#e8eaed;">' + r.email + '</td>' +
      '<td style="padding:5px 10px;font-size:11px;font-weight:700;color:' + clr + ';">' + r.evName.replace('login_','') + '</td>' +
      '<td style="padding:5px 10px;font-size:11px;color:#9aa0a6;">' + [r.city,r.country].filter(Boolean).join(', ') + '</td>' +
      '<td style="padding:5px 10px;font-size:11px;color:#9aa0a6;">' + r.ip + '</td></tr>';
  }).join('');

  return '<!DOCTYPE html><html><head><meta charset="UTF-8"></head>' +
    '<body style="margin:0;padding:0;background:#0f1923;font-family:Arial,sans-serif;">' +
    '<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1923;padding:24px 0;">' +
    '<tr><td align="center"><table width="680" cellpadding="0" cellspacing="0" style="background:#152232;border-radius:8px;overflow:hidden;max-width:680px;">' +
    '<tr><td style="background:linear-gradient(135deg,#0a1628,#0d1f3c,#0a1628);padding:24px;text-align:center;">' +
    '<div style="font-size:22px;font-weight:700;color:#00c8ff;letter-spacing:2px;text-transform:uppercase;">Workspace Watchdog</div>' +
    '<div style="font-size:18px;font-weight:700;color:#e8eaed;margin-top:6px;">' + title + filter + '</div>' +
    '<div style="font-size:12px;color:#9aa0a6;margin-top:4px;">Last ' + d.daysBack + ' days &mdash; Generated ' + d.generatedAt + '</div>' +
    '</td></tr>' +
    '<tr><td style="padding:20px 24px 8px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1e3a5f;border-radius:6px;"><tr>' +
    statBox('Total Events',  d.totalEvents,  '#8ab4f8') + statBox('Successful',    d.successCount, '#81c995') +
    statBox('Failed',        d.failCount,    d.failCount > 0 ? '#ef5350' : '#81c995') +
    statBox('Fail Rate',     d.failRate + '%', parseFloat(d.failRate) > 10 ? '#ef5350' : '#81c995') +
    statBox('Outside US',   d.outsideCount,  d.outsideCount > 0 ? '#f44336' : '#81c995') +
    statBox('Unique Users', d.uniqueUsers,   '#8ab4f8') +
    '</tr></table></td></tr>' +
    (d.suspRows.length ? sectionHdr('Suspicious Events (' + d.suspRows.length + ')') +
      '<tr><td colspan="2" style="padding:0 24px 12px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1a2e45;border-radius:6px;">' +
      '<tr style="background:#1e3a5f;"><th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:left;">TIME</th>' +
      '<th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:left;">EMAIL</th>' +
      '<th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:left;">REASON</th>' +
      '<th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:left;">DETAILS</th></tr>' +
      suspHtml + '</table></td></tr>' : '') +
    (d.topFailed.length ? sectionHdr('Top Failed Login Accounts') +
      '<tr><td colspan="2" style="padding:0 24px 12px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1a2e45;border-radius:6px;">' +
      '<tr style="background:#1e3a5f;"><th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:left;">EMAIL</th>' +
      '<th style="padding:6px 12px;font-size:10px;color:#8ab4f8;text-align:right;">FAILURES</th></tr>' +
      topFailedRows + '</table></td></tr>' : '') +
    (d.rows.length && d.reportType !== 'summary' ? sectionHdr('Recent Activity (last 50 events)') +
      '<tr><td colspan="2" style="padding:0 24px 16px;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#1a2e45;border-radius:6px;">' +
      '<tr style="background:#1e3a5f;"><th style="padding:5px 10px;font-size:10px;color:#8ab4f8;text-align:left;">TIME</th>' +
      '<th style="padding:5px 10px;font-size:10px;color:#8ab4f8;text-align:left;">EMAIL</th>' +
      '<th style="padding:5px 10px;font-size:10px;color:#8ab4f8;text-align:left;">EVENT</th>' +
      '<th style="padding:5px 10px;font-size:10px;color:#8ab4f8;text-align:left;">LOCATION</th>' +
      '<th style="padding:5px 10px;font-size:10px;color:#8ab4f8;text-align:left;">IP</th></tr>' +
      recentRows + '</table></td></tr>' : '') +
    '<tr><td style="padding:16px 24px;text-align:center;border-top:1px solid #1e3a5f;">' +
    '<div style="font-size:11px;color:#3a5070;">Generated by Workspace Watchdog</div>' +
    '</td></tr></table></td></tr></table></body></html>';
}
