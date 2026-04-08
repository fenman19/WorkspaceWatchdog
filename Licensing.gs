/* global AdminReports, AdminDirectory */
/**
 * Licensing.gs — GitHub-based auto-update system, version management,
 *                 and the UPDATER configuration constant.
 */

const UPDATER = {
  REPO_RAW: 'https://raw.githubusercontent.com/WorkspaceWatchdog/WorkspaceWatchdog/main',
  VERSION_URL: 'https://raw.githubusercontent.com/WorkspaceWatchdog/WorkspaceWatchdog/main/version.json',
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
