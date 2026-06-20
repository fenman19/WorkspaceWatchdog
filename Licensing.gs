/* global AdminReports, AdminDirectory */
/**
 * Licensing.gs — GitHub-based auto-update system, version management,
 *                 license validation, and the UPDATER configuration constant.
 */

const UPDATER = {
  REPO_RAW: 'https://raw.githubusercontent.com/fenman19/WorkspaceWatchdog/refactor/split-gs-files',
  VERSION_URL: 'https://raw.githubusercontent.com/fenman19/WorkspaceWatchdog/refactor/split-gs-files/version.json',
  FILES: [
    { name: 'Code',         filename: 'Code.gs',           type: 'SERVER_JS' },
    { name: 'Utils',        filename: 'Utils.gs',           type: 'SERVER_JS' },
    { name: 'Setup',        filename: 'Setup.gs',           type: 'SERVER_JS' },
    { name: 'Sync',         filename: 'Sync.gs',            type: 'SERVER_JS' },
    { name: 'Geo',          filename: 'Geo.gs',             type: 'SERVER_JS' },
    { name: 'OrgUnit',      filename: 'OrgUnit.gs',         type: 'SERVER_JS' },
    { name: 'Detection',    filename: 'Detection.gs',       type: 'SERVER_JS' },
    { name: 'Alerts',       filename: 'Alerts.gs',          type: 'SERVER_JS' },
    { name: 'Reports',      filename: 'Reports.gs',         type: 'SERVER_JS' },
    { name: 'MapData',      filename: 'MapData.gs',         type: 'SERVER_JS' },
    { name: 'Licensing',    filename: 'Licensing.gs',       type: 'SERVER_JS' },
    { name: 'Archive',      filename: 'Archive.gs',         type: 'SERVER_JS' },
    { name: 'YearEnd',      filename: 'YearEnd.gs',         type: 'SERVER_JS' },
    { name: 'SetupWizard',  filename: 'SetupWizard.html',   type: 'HTML'      },
    { name: 'Settings',     filename: 'Settings.html',      type: 'HTML'      },
    { name: 'Updates',      filename: 'Updates.html',       type: 'HTML'      },
    { name: 'LiveMap',      filename: 'LiveMap.html',        type: 'HTML'      }
  ],
  PROP_VERSION:    'WW_INSTALLED_VERSION',
  PROP_LAST_CHECK: 'WW_LAST_UPDATE_CHECK'
};

// ===== License Validation & Storage ==========================================

// Grace periods (days) from expiration date before full shutdown, by tier.
// Map access is disabled immediately at expiration for every tier; full
// shutdown (sync/detection/alerts stop) happens after the grace period below.
const LICENSE_GRACE_DAYS = {
  trial:    7,
  paid:     30,
  lifetime: Infinity // never shuts down
};

const LICENSE_PROPS = {
  KEY:     'WW_LICENSE_KEY',
  TIER:    'WW_LICENSE_TIER',
  DOMAIN:  'WW_LICENSE_DOMAIN',
  EXPIRES: 'WW_LICENSE_EXPIRES',      // yyyy-MM-dd, as returned by license server
  LAST_CHECK: 'WW_LICENSE_LAST_CHECK', // ISO timestamp of last server validation
  LAST_POPUP: 'WW_LICENSE_LAST_POPUP'  // yyyy-MM-dd, last date the shutdown popup was shown
};

function validateAndStoreLicense(token) {
  token = String(token || '').trim();
  if (!token) return { ok: false, error: 'missing_token' };

  // Derive tier from token prefix
  var tier = 'unknown';
  if (token.indexOf('wwt-') === 0)      tier = 'trial';
  else if (token.indexOf('wwp-') === 0) tier = 'paid';
  else if (token.indexOf('wwl-') === 0) tier = 'lifetime';
  else return { ok: false, error: 'invalid_token_format' };

  // Get domain from active user's email
  var email  = Session.getEffectiveUser().getEmail();
  var domain = email.split('@')[1] || '';
  if (!domain) return { ok: false, error: 'could_not_determine_domain' };

  // Call Cloudflare Worker → License Server
  var workerUrl = 'https://ww-license.wild-credit-7442.workers.dev' +
    '?action=validate&token=' + encodeURIComponent(token) +
    '&domain=' + encodeURIComponent(domain);

  try {
    var resp = UrlFetchApp.fetch(workerUrl, { muteHttpExceptions: true, deadline: 10 });
    var code = resp.getResponseCode();
    if (code !== 200) return { ok: false, error: 'worker_http_' + code };

    var data = JSON.parse(resp.getContentText() || '{}');
    var serverExpires = data.data && data.data.expires ? data.data.expires : '';
    var serverTier    = data.data && data.data.tier    ? data.data.tier    : tier;

    if (!data.success) {
      // Even on failure (e.g. expired), store what the server told us about
      // expiry/tier when available, so _getLicenseState_ has accurate data
      // without requiring a successful re-activation.
      if (serverExpires) {
        var failProps = {};
        failProps[LICENSE_PROPS.EXPIRES] = serverExpires;
        failProps[LICENSE_PROPS.TIER]    = serverTier;
        PropertiesService.getScriptProperties().setProperties(failProps);
      }
      return { ok: false, error: data.result || data.error || 'validation_failed' };
    }

    // Store in Script Properties
    var okProps = {};
    okProps[LICENSE_PROPS.KEY]        = token;
    okProps[LICENSE_PROPS.TIER]       = serverTier;
    okProps[LICENSE_PROPS.DOMAIN]     = domain;
    okProps[LICENSE_PROPS.EXPIRES]    = serverExpires;
    okProps[LICENSE_PROPS.LAST_CHECK] = new Date().toISOString();
    PropertiesService.getScriptProperties().setProperties(okProps);

    return { ok: true, tier: serverTier, domain: domain, expires: serverExpires };

  } catch (e) {
    return { ok: false, error: 'fetch_error: ' + (e.message || String(e)) };
  }
}

// ===== License State (banners, map lock, shutdown) ===========================
//
// Single source of truth for "what should the product do right now given the
// stored license". Pure read of Script Properties — does NOT call the license
// server (see _maybeRevalidateLicense_ for that). Phases:
//   'unlicensed' — no token ever activated
//   'lifetime'   — wwl- token, never expires/locks
//   'active'     — valid, more than 15 days from expiry
//   'warn15'     — 8-15 days from expiry
//   'warn7'      — 2-7 days from expiry
//   'warn1'      — 0-1 days from expiry (today or tomorrow)
//   'mapLocked'  — expired, within grace period (map disabled, sync still runs)
//   'shutdown'   — expired, past grace period (everything disabled)
function _getLicenseState_() {
  var p = PropertiesService.getScriptProperties();
  var tier    = p.getProperty(LICENSE_PROPS.TIER)    || '';
  var expires = p.getProperty(LICENSE_PROPS.EXPIRES) || '';

  if (!tier) return { tier: '', phase: 'unlicensed', daysUntil: null, expiresOn: '' };
  if (tier === 'lifetime') return { tier: tier, phase: 'lifetime', daysUntil: null, expiresOn: '' };

  if (!expires) return { tier: tier, phase: 'unlicensed', daysUntil: null, expiresOn: '' };

  var expDate  = new Date(expires + 'T23:59:59'); // expires at end of that calendar day
  var now      = new Date();
  var msPerDay = 24 * 60 * 60 * 1000;
  var daysUntil = Math.ceil((expDate.getTime() - now.getTime()) / msPerDay);

  if (daysUntil > 15) return { tier: tier, phase: 'active', daysUntil: daysUntil, expiresOn: expires };
  if (daysUntil > 7)  return { tier: tier, phase: 'warn15', daysUntil: daysUntil, expiresOn: expires };
  if (daysUntil > 1)  return { tier: tier, phase: 'warn7',  daysUntil: daysUntil, expiresOn: expires };
  if (daysUntil >= 0) return { tier: tier, phase: 'warn1',  daysUntil: daysUntil, expiresOn: expires };

  // Expired — daysUntil is negative from here on (days since expiry = -daysUntil)
  var daysSinceExpiry = -daysUntil;
  var graceDays = LICENSE_GRACE_DAYS[tier] !== undefined ? LICENSE_GRACE_DAYS[tier] : 7;

  if (daysSinceExpiry >= graceDays) {
    return { tier: tier, phase: 'shutdown', daysUntil: daysUntil, expiresOn: expires };
  }
  return { tier: tier, phase: 'mapLocked', daysUntil: daysUntil, expiresOn: expires };
}

// Public wrapper around _getLicenseState_ for client-side calls (e.g. the
// LiveMap expiry banner). Only exposes the fields the client needs — never
// the raw token.
function getLicenseStateForClient() {
  var state = _getLicenseState_();
  return { phase: state.phase, daysUntil: state.daysUntil, expiresOn: state.expiresOn };
}

// Re-validates against the license server at most once per ~20 hours (so it's
// effectively daily regardless of how often onOpen/sync fire) and refreshes
// the locally stored expiry/tier/status. Safe to call often — it no-ops most
// of the time. Never throws; license state should never block normal use due
// to a network hiccup talking to the Worker.
function _maybeRevalidateLicense_() {
  var p = PropertiesService.getScriptProperties();
  var token = p.getProperty(LICENSE_PROPS.KEY);
  if (!token) return; // never activated — nothing to revalidate

  var lastCheck = p.getProperty(LICENSE_PROPS.LAST_CHECK);
  if (lastCheck) {
    var hoursSince = (Date.now() - new Date(lastCheck).getTime()) / (1000 * 60 * 60);
    if (hoursSince < 20) return;
  }

  // Snapshot local state before overwriting, so we can detect a mismatch
  // between what was stored locally and what the server actually says.
  var beforeTier    = p.getProperty(LICENSE_PROPS.TIER)    || '';
  var beforeExpires = p.getProperty(LICENSE_PROPS.EXPIRES) || '';

  try {
    validateAndStoreLicense(token);
  } catch (e) {
    // Network/server issue — leave existing stored state as-is, try again later.
    return;
  }

  var afterTier    = p.getProperty(LICENSE_PROPS.TIER)    || '';
  var afterExpires = p.getProperty(LICENSE_PROPS.EXPIRES) || '';

  _flagIfLicenseMismatch_(token, beforeTier, beforeExpires, afterTier, afterExpires);
}

// Compares locally-stored license state (before a revalidation) against what
// the server just confirmed (after). Flags only discrepancies that favor the
// customer — e.g. local claimed a higher tier or a later expiry than the
// server actually has on record — which is the pattern manual Script
// Properties tampering would produce. This is visibility only: it never
// blocks anything or alters local state itself; validateAndStoreLicense
// has already corrected the local values by the time this runs.
function _flagIfLicenseMismatch_(token, beforeTier, beforeExpires, afterTier, afterExpires) {
  if (!beforeTier || !afterTier) return; // nothing to compare on first-ever check

  var tierRank = { trial: 0, paid: 1, lifetime: 2 };
  var beforeRank = tierRank[beforeTier] !== undefined ? tierRank[beforeTier] : -1;
  var afterRank  = tierRank[afterTier]  !== undefined ? tierRank[afterTier]  : -1;

  var tierInflated = beforeRank > afterRank;
  var expiresInflated = (beforeTier === afterTier) &&
    beforeExpires && afterExpires && beforeExpires > afterExpires;

  if (!tierInflated && !expiresInflated) return;

  var domain = PropertiesService.getScriptProperties().getProperty(LICENSE_PROPS.DOMAIN) || '';
  var notes = 'Local state before revalidation (tier=' + beforeTier + ', expires=' + beforeExpires +
    ') did not match server (tier=' + afterTier + ', expires=' + afterExpires + ').';

  try {
    var flagUrl = 'https://ww-license.wild-credit-7442.workers.dev' +
      '?action=flag_mismatch&token=' + encodeURIComponent(token) +
      '&domain=' + encodeURIComponent(domain) +
      '&notes=' + encodeURIComponent(notes);
    UrlFetchApp.fetch(flagUrl, { muteHttpExceptions: true, deadline: 10 });
  } catch (e) {
    // Best-effort only — never let logging failure affect anything else.
  }
}

// ===== Version & Update System ===============================================

function getInstalledVersion() {
  const v = PropertiesService.getScriptProperties().getProperty(UPDATER.PROP_VERSION);
  return v || '0.0.0';
}

function saveInstalledVersion(version) {
  PropertiesService.getScriptProperties().setProperty(UPDATER.PROP_VERSION, version);
}

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

function getVersionInfo() {
  try {
    const resp = UrlFetchApp.fetch(UPDATER.VERSION_URL, { muteHttpExceptions: true, deadline: 5 });
    if (resp.getResponseCode() === 200) return JSON.parse(resp.getContentText());
  } catch(e) {}
  return null;
}

function applyUpdate() {
  try {
    if (_getLicenseState_().phase === 'shutdown') {
      return { ok: false, message: 'Updates are paused because your license has expired and the grace period has ended. Renew at workspacewatchdog.com to resume updates.' };
    }

    const versionResp = UrlFetchApp.fetch(UPDATER.VERSION_URL, { muteHttpExceptions: true });
    if (versionResp.getResponseCode() !== 200) {
      return { ok: false, message: 'Could not fetch version info from GitHub.' };
    }
    const remote = JSON.parse(versionResp.getContentText());

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

    const files = UPDATER.FILES.map((f, i) => ({
      name:   f.name,
      type:   f.type,
      source: responses[i].getContentText()
    }));

    try {
      const manifestResp = UrlFetchApp.fetch(
        UPDATER.REPO_RAW + '/appsscript.json',
        { muteHttpExceptions: true }
      );
      if (manifestResp.getResponseCode() === 200) {
        files.push({ name: 'appsscript', type: 'JSON', source: manifestResp.getContentText() });
      }
    } catch(e) { /* manifest optional */ }

    const scriptId = ScriptApp.getScriptId();
    const token    = ScriptApp.getOAuthToken();
    const apiUrl   = 'https://script.googleapis.com/v1/projects/' + scriptId + '/content';

    const apiResp = UrlFetchApp.fetch(apiUrl, {
      method:  'PUT',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      payload:            JSON.stringify({ files }),
      muteHttpExceptions: true
    });

    const apiCode = apiResp.getResponseCode();
    if (apiCode !== 200) {
      const body = apiResp.getContentText();
      if (body.indexOf('Apps Script API has not been used') !== -1 ||
          body.indexOf('accessNotConfigured') !== -1) {
        return { ok: false, message: 'ENABLE_API', scriptId: scriptId };
      }
      return { ok: false, message: 'Apps Script API returned HTTP ' + apiCode + ': ' + body };
    }

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

function _versionCompare_(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function showUpdatesPanel() {
  const html = HtmlService.createHtmlOutputFromFile('Updates')
    .setTitle('Workspace Watchdog — Updates')
    .setWidth(620)
    .setHeight(580);
  SpreadsheetApp.getUi().showModalDialog(html, 'Workspace Watchdog — Updates');
}
