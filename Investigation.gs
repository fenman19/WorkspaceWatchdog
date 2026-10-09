/* global AdminReports */



/**

 * Investigation.gs — Workspace Bloodhound investigation backend.

 *

 * Source-by-source investigator backend for LiveMap.html.

 * No investigation sheets are created.

 * Geolocation uses CacheService + external providers.

 */



const WW_INVESTIGATION = {

  MAX_RESULTS: 1000,

  MAX_RECORDS_PER_SOURCE: 15000,

  MAX_RANGE_DAYS: 30,

  GEO_CACHE_SECONDS: 21600,

  GEO_CACHE_PREFIX: 'wwinv:geo:v2:',

  MAX_GEO_LOOKUPS_PER_SOURCE: 300,

  SOURCES: {

    login:         { label: 'Login / User Activity', app: 'login' },

    gmail:         { label: 'Gmail Activity', app: 'gmail' },

    drive:         { label: 'Drive Activity', app: 'drive' },

    admin:         { label: 'Admin Activity', app: 'admin' },

    takeout:       { label: 'Takeout Activity', app: 'takeout' },

    token:         { label: 'OAuth / Token Activity', app: 'token' },

    user_accounts: { label: 'User Accounts', app: 'user_accounts' }

  }

};



/**

 * Public RPC used by LiveMap.html.

 * Runs ONE source per call so large investigations don't require one huge response.

 */

function runWatchdogInvestigationSource(request) {

  _requireAllowedUser_();

  _requireMapLicense_();



  request = request || {};



  const sourceKey = String(request.source || '').trim();

  const source = WW_INVESTIGATION.SOURCES[sourceKey];

  const email = String(request.email || '').trim().toLowerCase();



  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {

    throw new Error('A valid user email is required.');

  }



  if (!source) {

    throw new Error('Invalid investigation source: ' + sourceKey);

  }



  const start = new Date(request.start);

  const end = new Date(request.end);



  if (isNaN(start.getTime()) || isNaN(end.getTime())) {

    throw new Error('A valid investigation time range is required.');

  }



  if (start >= end) {

    throw new Error('The investigation start must be earlier than the end.');

  }



  const days = (end.getTime() - start.getTime()) / 86400000;



  if (days > WW_INVESTIGATION.MAX_RANGE_DAYS) {

    throw new Error(

      'Investigations are limited to ' +

      WW_INVESTIGATION.MAX_RANGE_DAYS +

      ' days per request.'

    );

  }



  if (sourceKey === 'gmail' && days > 30) {

    throw new Error('Gmail audit requests cannot span more than 30 days.');

  }



  const activities = _wwInvFetchAllActivities_(

    email,

    source.app,

    start.toISOString(),

    end.toISOString()

  );



  const normalized = _wwInvNormalizeActivities_(sourceKey, activities);



  let geoMap = {};

  if (sourceKey === 'login' || sourceKey === 'drive') {

    geoMap = _wwInvGetGeoMapForRows_(normalized);

  }



  return {

    source: sourceKey,

    label: source.label,

    count: normalized.length,

    truncated: activities.__truncated === true,

    columns: _wwInvColumnsForSource_(sourceKey),

    rows: normalized.map(function(r) {

      return _wwInvDisplayRow_(sourceKey, r, geoMap);

    })

  };

}





/**

 * Fetch all Admin Reports activities for one source with pagination.

 */

/**
 * Create a new Google Sheet case file for the current investigation.
 * The browser then sends each successful source in manageable chunks.
 */
function createWatchdogInvestigationSheet(request) {
  _requireAllowedUser_();
  _requireMapLicense_();
  request = request || {};

  const email = String(request.email || '').trim().toLowerCase();
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    throw new Error('A valid target account is required before saving an investigation.');
  }

  const start = String(request.start || '').trim();
  const end = String(request.end || '').trim();
  const sourceSummaries = Array.isArray(request.sources) ? request.sources : [];
  const sourceErrors = Array.isArray(request.errors) ? request.errors : [];
  const tz = (typeof CONFIG !== 'undefined' && CONFIG.TZ) ? CONFIG.TZ : 'America/Chicago';
  const now = new Date();
  const stamp = Utilities.formatDate(now, tz, 'yyyy-MM-dd HHmm');
  const safeEmail = email.replace(/[^a-z0-9@._-]+/gi, '_');
  const name = 'Workspace Bloodhound - ' + safeEmail + ' - ' + stamp;

  const ss = SpreadsheetApp.create(name);
  const summary = ss.getSheets()[0];
  summary.setName('Summary');

  const totalRecords = sourceSummaries.reduce(function(n, s) {
    return n + Number((s && s.count) || 0);
  }, 0);

  const info = [
    ['Workspace Bloodhound Investigation', ''],
    ['Target Account', email],
    ['From', start],
    ['To', end],
    ['Created', Utilities.formatDate(now, tz, 'MM/dd/yyyy hh:mm:ss a')],
    ['Sources Completed', sourceSummaries.length],
    ['Source Errors', sourceErrors.length],
    ['Total Records', totalRecords]
  ];

  summary.getRange(1, 1, info.length, 2).setValues(info.map(function(row) {
    return row.map(_wwInvSheetSafeCell_);
  }));
  summary.getRange('A1:B1').setBackground('#0f172a').setFontColor('#ffffff').setFontWeight('bold');
  summary.getRange('A2:A8').setFontWeight('bold');
  summary.setColumnWidth(1, 170);
  summary.setColumnWidth(2, 440);

  let row = info.length + 3;
  summary.getRange(row, 1, 1, 4).setValues([['Source', 'Records', 'Truncated', 'Status']]);
  summary.getRange(row, 1, 1, 4).setBackground('#182235').setFontColor('#ffffff').setFontWeight('bold');
  row++;

  const sourceRows = sourceSummaries.map(function(s) {
    return [String((s && s.label) || (s && s.source) || ''), Number((s && s.count) || 0), (s && s.truncated) ? 'YES' : 'NO', 'OK'];
  });
  sourceErrors.forEach(function(e) {
    sourceRows.push([String((e && e.label) || (e && e.source) || ''), 0, '', 'ERROR: ' + String((e && e.error) || 'Unknown error')]);
  });

  if (sourceRows.length) {
    _wwInvEnsureSheetSize_(summary, row + sourceRows.length - 1, 4);
    summary.getRange(row, 1, sourceRows.length, 4).setValues(sourceRows.map(function(r) { return r.map(_wwInvSheetSafeCell_); }));
    summary.getRange(row, 1, sourceRows.length, 4).setWrap(true);
  }

  const token = Utilities.getUuid();
  CacheService.getUserCache().put('wwinv:sheet-export:' + token, ss.getId(), 3600);
  return { token: token, spreadsheetId: ss.getId(), url: ss.getUrl(), name: ss.getName() };
}

/** Append one chunk of one source to the investigation case Sheet. */
function appendWatchdogInvestigationSheetChunk(request) {
  _requireAllowedUser_();
  _requireMapLicense_();
  request = request || {};

  const token = String(request.token || '');
  const spreadsheetId = _wwInvExportSpreadsheetId_(token);
  const sourceKey = String(request.source || '').trim();
  const source = sourceKey === 'timeline' ? { label: 'Timeline' } : WW_INVESTIGATION.SOURCES[sourceKey];
  if (!source) throw new Error('Invalid investigation source: ' + sourceKey);

  const columns = Array.isArray(request.columns) ? request.columns : [];
  const rows = Array.isArray(request.rows) ? request.rows : [];
  const firstChunk = request.firstChunk === true;
  if (!columns.length) throw new Error('No columns were supplied for ' + source.label + '.');

  const ss = SpreadsheetApp.openById(spreadsheetId);
  const tabName = _wwInvExportTabName_(sourceKey);
  let sh = ss.getSheetByName(tabName);

  if (firstChunk) {
    if (sh) ss.deleteSheet(sh);
    sh = ss.insertSheet(tabName);
    _wwInvEnsureSheetSize_(sh, 1, columns.length);
    sh.getRange(1, 1, 1, columns.length).setValues([columns.map(_wwInvSheetSafeCell_)]);
    sh.getRange(1, 1, 1, columns.length).setBackground('#182235').setFontColor('#ffffff').setFontWeight('bold').setWrap(true);
    sh.setFrozenRows(1);
    sh.setColumnWidths(1, columns.length, 130);
    columns.forEach(function(col, index) {
      const label = String(col || '').toLowerCase();
      if (label.indexOf('raw') >= 0 || label.indexOf('url') >= 0 || label.indexOf('subject') >= 0) sh.setColumnWidth(index + 1, 320);
      else if (label.indexOf('email') >= 0 || label.indexOf('recipient') >= 0 || label.indexOf('sender') >= 0) sh.setColumnWidth(index + 1, 220);
      else if (label.indexOf('timestamp') >= 0) sh.setColumnWidth(index + 1, 175);
    });
  }

  if (!sh) throw new Error('The destination tab for ' + source.label + ' has not been initialized.');

  if (rows.length) {
    const safeRows = rows.map(function(inputRow) {
      const normalized = [];
      for (let i = 0; i < columns.length; i++) normalized.push(_wwInvSheetSafeCell_(inputRow && inputRow[i] !== undefined ? inputRow[i] : ''));
      return normalized;
    });
    const startRow = sh.getLastRow() + 1;
    _wwInvEnsureSheetSize_(sh, startRow + safeRows.length - 1, columns.length);
    const dataRange = sh.getRange(startRow, 1, safeRows.length, columns.length);
    dataRange.setValues(safeRows);
    _wwInvApplyExportHighlights_(dataRange, columns, safeRows, sourceKey);
  }

  return { source: sourceKey, tab: tabName, appended: rows.length };
}

/** Finish formatting and release the one-hour export token. */
function finalizeWatchdogInvestigationSheet(request) {
  _requireAllowedUser_();
  _requireMapLicense_();
  request = request || {};
  const token = String(request.token || '');
  const spreadsheetId = _wwInvExportSpreadsheetId_(token);
  const ss = SpreadsheetApp.openById(spreadsheetId);

  ss.getSheets().forEach(function(sh) {
    const lastRow = sh.getLastRow();
    const lastCol = sh.getLastColumn();
    if (lastRow > 1 && lastCol > 0 && sh.getName() !== 'Summary') {
      const range = sh.getRange(1, 1, lastRow, lastCol);
      if (!range.getFilter()) range.createFilter();
    }
  });

  CacheService.getUserCache().remove('wwinv:sheet-export:' + token);
  return { spreadsheetId: ss.getId(), url: ss.getUrl(), name: ss.getName() };
}


/**
 * Apply Bloodhound's on-screen visual cues to exported Google Sheets.
 *
 * Timeline:
 *   SUSPECT IP      -> red row
 *   LIKELY RELATED  -> yellow row
 *   OTHER IP        -> blue row
 *   UNKNOWN         -> gray row
 *
 * Source tabs:
 *   Gmail LINK CLICKED / ATTACHMENT LINK CLICKED / downloaded activity -> red row
 *   FAILURE / Suspicious=YES / suspicious text                         -> red cell
 *   SUCCESS / NO                                                       -> green cell
 *   AUTHORIZE / authorization text                                     -> yellow cell
 */
function _wwInvApplyExportHighlights_(range, columns, rows, sourceKey) {
  if (!range || !rows || !rows.length || !columns || !columns.length) return;

  const RED_BG = '#fce8e6';
  const RED_FG = '#b31412';
  const YELLOW_BG = '#fef7e0';
  const YELLOW_FG = '#b06000';
  const GREEN_BG = '#e6f4ea';
  const GREEN_FG = '#137333';
  const BLUE_BG = '#e8f0fe';
  const BLUE_FG = '#1967d2';
  const GRAY_BG = '#f1f3f4';
  const GRAY_FG = '#5f6368';
  const DEFAULT_BG = '#ffffff';
  const DEFAULT_FG = '#202124';

  const rowCount = rows.length;
  const colCount = columns.length;
  const backgrounds = Array.from({length: rowCount}, function() {
    return Array(colCount).fill(DEFAULT_BG);
  });
  const fontColors = Array.from({length: rowCount}, function() {
    return Array(colCount).fill(DEFAULT_FG);
  });
  const fontWeights = Array.from({length: rowCount}, function() {
    return Array(colCount).fill('normal');
  });

  const lowerColumns = columns.map(function(c) { return String(c || '').toLowerCase(); });
  const trackIndex = lowerColumns.indexOf('track');
  const mailEventIndex = lowerColumns.indexOf('mail event');

  function paintRow(r, bg, fg) {
    for (let c = 0; c < colCount; c++) {
      backgrounds[r][c] = bg;
      fontColors[r][c] = fg;
    }
  }

  function paintCell(r, c, bg, fg, bold) {
    backgrounds[r][c] = bg;
    fontColors[r][c] = fg;
    if (bold) fontWeights[r][c] = 'bold';
  }

  rows.forEach(function(row, r) {
    row = row || [];

    // Timeline gets row-level classification colors.
    if (sourceKey === 'timeline' && trackIndex >= 0) {
      const track = String(row[trackIndex] || '').toUpperCase();
      if (track === 'SUSPECT IP') paintRow(r, RED_BG, RED_FG);
      else if (track === 'LIKELY RELATED') paintRow(r, YELLOW_BG, YELLOW_FG);
      else if (track === 'OTHER IP') paintRow(r, BLUE_BG, BLUE_FG);
      else if (track === 'UNKNOWN') paintRow(r, GRAY_BG, GRAY_FG);
      if (track) fontWeights[r][trackIndex] = 'bold';
    }

    // Match the Bloodhound table behavior for Gmail high-risk rows.
    if (sourceKey === 'gmail' && mailEventIndex >= 0) {
      const mailEvent = String(row[mailEventIndex] || '').toUpperCase();
      if (
        mailEvent.indexOf('LINK CLICKED') >= 0 ||
        mailEvent.indexOf('ATTACHMENT DOWNLOADED') >= 0 ||
        mailEvent.indexOf('ATTACHMENT PREVIEWED') >= 0
      ) {
        paintRow(r, RED_BG, RED_FG);
        fontWeights[r][mailEventIndex] = 'bold';
      }
    }

    // Cell-level cues across all source sheets.
    for (let c = 0; c < colCount; c++) {
      const value = String(row[c] == null ? '' : row[c]).trim();
      const upper = value.toUpperCase();
      if (!upper) continue;

      if (
        upper === 'FAILURE' ||
        upper === 'YES' ||
        upper.indexOf('LINK CLICKED') >= 0 ||
        upper.indexOf('ATTACHMENT DOWNLOADED') >= 0 ||
        upper.indexOf('ATTACHMENT PREVIEWED') >= 0 ||
        upper.indexOf('SUSPICIOUS') >= 0
      ) {
        paintCell(r, c, RED_BG, RED_FG, true);
      } else if (
        upper === 'SUCCESS' ||
        upper === 'NO'
      ) {
        paintCell(r, c, GREEN_BG, GREEN_FG, true);
      } else if (
        upper.indexOf('AUTHORIZE') >= 0 ||
        upper.indexOf('AUTHORIZATION') >= 0 ||
        upper.indexOf('OAUTH') >= 0 && upper.indexOf('GRANT') >= 0
      ) {
        paintCell(r, c, YELLOW_BG, YELLOW_FG, true);
      }
    }
  });

  range.setBackgrounds(backgrounds);
  range.setFontColors(fontColors);
  range.setFontWeights(fontWeights);
}

function _wwInvExportSpreadsheetId_(token) {
  if (!token) throw new Error('Missing investigation export token.');
  const id = CacheService.getUserCache().get('wwinv:sheet-export:' + token);
  if (!id) throw new Error('The investigation export session expired. Click Save to Google Sheet again.');
  return id;
}

function _wwInvExportTabName_(sourceKey) {
  const names = {
    timeline: 'Timeline', login: 'Login Activity', gmail: 'Gmail Activity', drive: 'Drive Activity', admin: 'Admin Activity',
    takeout: 'Takeout Activity', token: 'OAuth - Token Activity', user_accounts: 'User Accounts'
  };
  return names[sourceKey] || String(sourceKey || 'Results').slice(0, 100);
}

function _wwInvSheetSafeCell_(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Object.prototype.toString.call(value) === '[object Date]') return value;
  let text = (typeof value === 'object') ? JSON.stringify(value) : String(value);
  if (/^[=+\-@]/.test(text)) text = "'" + text;
  return text;
}

function _wwInvEnsureSheetSize_(sheet, neededRows, neededCols) {
  const rows = Math.max(1, Number(neededRows) || 1);
  const cols = Math.max(1, Number(neededCols) || 1);
  if (sheet.getMaxRows() < rows) sheet.insertRowsAfter(sheet.getMaxRows(), rows - sheet.getMaxRows());
  if (sheet.getMaxColumns() < cols) sheet.insertColumnsAfter(sheet.getMaxColumns(), cols - sheet.getMaxColumns());
}


function _wwInvFetchAllActivities_(userKey, applicationName, startTime, endTime) {

  if (typeof AdminReports === 'undefined' || !AdminReports.Activities) {

    throw new Error('Admin Reports service is not enabled.');

  }



  const items = [];

  let pageToken = null;

  let truncated = false;



  do {

    const args = {

      startTime: startTime,

      endTime: endTime,

      maxResults: WW_INVESTIGATION.MAX_RESULTS

    };



    if (pageToken) args.pageToken = pageToken;



    const response = _reportsListSafe_

      ? _reportsListSafe_(userKey, applicationName, args)

      : AdminReports.Activities.list(userKey, applicationName, args);



    if (response && response.items) {

      const remaining = WW_INVESTIGATION.MAX_RECORDS_PER_SOURCE - items.length;



      if (remaining <= 0) {

        truncated = true;

        break;

      }



      if (response.items.length > remaining) {

        Array.prototype.push.apply(items, response.items.slice(0, remaining));

        truncated = true;

        break;

      }



      Array.prototype.push.apply(items, response.items);

    }



    pageToken = response && response.nextPageToken ? response.nextPageToken : null;



    if (items.length >= WW_INVESTIGATION.MAX_RECORDS_PER_SOURCE && pageToken) {

      truncated = true;

      break;

    }



    if (pageToken) Utilities.sleep(100);

  } while (pageToken);



  Object.defineProperty(items, '__truncated', {

    value: truncated,

    enumerable: false

  });



  return items;

}





/**

 * Normalize Admin Reports activity into a common row object.

 */

function _wwInvNormalizeActivities_(sourceKey, activities) {

  const rows = [];



  (activities || []).forEach(function(activity) {

    const timestampISO = activity.id && activity.id.time ? activity.id.time : '';

    const actorEmail = activity.actor && activity.actor.email ? activity.actor.email : '';

    const actorIp = activity.ipAddress || '';

    const appName = activity.id && activity.id.applicationName

      ? activity.id.applicationName

      : sourceKey;



    const subdivisionCode = activity.networkInfo && Array.isArray(activity.networkInfo.subdivisionCode)

      ? activity.networkInfo.subdivisionCode.join(' | ')

      : (activity.networkInfo && activity.networkInfo.subdivisionCode) || '';



    const regionCode = activity.networkInfo && Array.isArray(activity.networkInfo.regionCode)

      ? activity.networkInfo.regionCode.join(' | ')

      : (activity.networkInfo && activity.networkInfo.regionCode) || '';



    const ipAsn = activity.networkInfo && activity.networkInfo.ipAsn

      ? (Array.isArray(activity.networkInfo.ipAsn)

          ? activity.networkInfo.ipAsn.join(' | ')

          : String(activity.networkInfo.ipAsn))

      : '';



    const events = activity.events && activity.events.length

      ? activity.events

      : [{ name: '', type: '', parameters: [] }];



    events.forEach(function(event) {

      const params = {};



      _wwInvFlattenParameters_(event.parameters || [], '', params);



      if (event.sensitiveParameters) {

        _wwInvFlattenParameters_(event.sensitiveParameters, 'sensitive', params);

      }



      const mailCode = _wwInvUseful_(params, [

        'event_info.mail_event_type',

        'mail_event_type'

      ]);



      const success = _wwInvUseful_(params, [

        'event_info.success',

        'success'

      ]);



      rows.push({

        timestampISO: timestampISO,

        timestamp: _wwInvFormatTime_(timestampISO),

        actorEmail: actorEmail,

        application: appName,

        eventType: event.type || '',

        eventName: event.name || '',

        ipAddress: actorIp,

        subdivisionCode: subdivisionCode,

        regionCode: regionCode,

        ipAsn: ipAsn,



        mailEvent: sourceKey === 'gmail'

          ? _wwInvGmailEventLabel_(mailCode)

          : mailCode,



        mailEventCode: mailCode,



        subject: _wwInvUseful_(params, [

          'message_info.subject',

          'message.subject',

          'subject',

          'message_subject'

        ]),



        messageId: _wwInvUseful_(params, [

          'message_info.rfc2822_message_id',

          'message_info.message_id',

          'message.message_id',

          'message_id',

          'rfc822_msg_id',

          'message_info.rfc822_msg_id'

        ]),



        targetUrl: _wwInvUseful_(params, [

          'event_info.target_link_url',

          'message_info.target_link_url',

          'target_link_url',

          'link_url',

          'url'

        ]),



        challengeType: _wwInvUseful_(params, [

          'event_info.challenge_type',

          'challenge_type'

        ]),



        loginType: _wwInvUseful_(params, [

          'event_info.login_type',

          'login_type'

        ]),



        client: _wwInvUseful_(params, [

          'client_context.application_name',

          'client_context.client_name',

          'application_name',

          'client_name'

        ]),



        sender: _wwInvUseful_(params, [

          'message_info.sender',

          'message.sender',

          'sender',

          'from_address',

          'sender_address'

        ]),



        recipients: _wwInvCleanDestinations_(

          _wwInvUseful_(params, [

            'message_info.flattened_destinations',

            'message_info.recipient',

            'message_info.recipients',

            'message.recipient',

            'recipient',

            'recipients',

            'to_address',

            'recipient_address'

          ])

        ),



        attachment: _wwInvUseful_(params, [

          'message_info.attachment_name',

          'message_info.attachment_names',

          'attachment_name',

          'attachment_names',

          'filename'

        ]),



        actionType: _wwInvUseful_(params, [

          'message_info.action_type',

          'event_info.action_type',

          'action_type'

        ]),



        linkDomains: _wwInvUseful_(params, [

          'message_info.link_domain',

          'message_info.link_domains',

          'link_domain',

          'link_domains'

        ]),



        attachmentCount: _wwInvUseful_(params, [

          'message_info.num_message_attachments',

          'num_message_attachments'

        ]),



        success: success,



        suspicious: _wwInvYesNo_(

          _wwInvUseful_(params, [

            'event_info.is_suspicious',

            'is_suspicious',

            'suspicious'

          ])

        ),



        challengeStatus: _wwInvUseful_(params, [

          'event_info.challenge_status',

          'challenge_status'

        ]),



        failureReason: _wwInvUseful_(params, [

          'event_info.login_failure_type',

          'login_failure_type',

          'failure_type',

          'failure_reason'

        ]),



        deviceId: _wwInvUseful_(params, [

          'device_id',

          'event_info.device_id',

          'client_context.device_id'

        ]),



        rawParameters: JSON.stringify(params)

      });

    });

  });



  rows.sort(function(a, b) {

    return String(a.timestampISO).localeCompare(String(b.timestampISO));

  });



  return rows;

}





/**

 * Source-specific columns expected by the v2 LiveMap Investigator UI.

 */

function _wwInvColumnsForSource_(sourceKey) {

  if (sourceKey === 'gmail') {

    return [

      'Timestamp',

      'Mail Event',

      'Mail Event Code',

      'Subject',

      'Sender',

      'Recipient(s)',

      'IP Address',

      'Target / Link URL',

      'Link Domain(s)',

      'Attachment Count',

      'Attachment',

      'Message ID',

      'Action Type',

      'Actor Email',

      'Application / Client',

      'Raw Parameters'

    ];

  }



  if (sourceKey === 'login') {

    return [

      'Timestamp',

      'Result',

      'Event',

      'IP Address',

      'City',

      'State / Region',

      'Country',

      'ISP',

      'ASN',

      'Suspicious',

      'Challenge Type',

      'Challenge Status',

      'Login Type',

      'Failure Reason',

      'Actor Email',

      'Device ID',

      'Application / Client',

      'Event Type',

      'Raw Parameters'

    ];

  }



  if (sourceKey === 'token') {

    return [

      'Timestamp',

      'Event',

      'App Name',

      'Client ID',

      'API',

      'Method',

      'Product',

      'Client Type',

      'IP Address',

      'Actor Email',

      'Scopes / Permissions',

      'Event Type',

      'Raw Parameters'

    ];

  }



  if (sourceKey === 'drive') {

    return [

      'Timestamp',

      'Event',

      'Item Name',

      'Item ID',

      'IP Address',

      'City',

      'State / Region',

      'Country',

      'ISP',

      'ASN',

      'Actor Email',

      'Owner',

      'Target User',

      'Visibility',

      'Event Type',

      'Raw Parameters'

    ];

  }



  return [

    'Timestamp',

    'Actor Email',

    'Application',

    'Event Type',

    'Event Name',

    'IP Address',

    'State / Subdivision',

    'Country / Region',

    'ASN',

    'Mail Event',

    'Subject',

    'Message ID',

    'Target / Link URL',

    'Challenge Type',

    'Login Type',

    'Application / Client',

    'Sender',

    'Recipient(s)',

    'Attachment',

    'Action Type',

    'Link Domain(s)',

    'Attachment Count',

    'Success',

    'Suspicious',

    'Challenge Status',

    'Failure Reason',

    'Device ID',

    'Raw Parameters'

  ];

}





/**

 * Convert normalized object into source-specific display row.

 */

function _wwInvDisplayRow_(sourceKey, r, geoMap) {

  geoMap = geoMap || {};



  if (sourceKey === 'gmail') {

    return [

      r.timestamp,

      r.mailEvent,

      r.mailEventCode,

      r.subject,

      r.sender,

      r.recipients,

      r.ipAddress,

      r.targetUrl,

      r.linkDomains,

      r.attachmentCount,

      r.attachment,

      r.messageId,

      r.actionType,

      r.actorEmail,

      r.client,

      r.rawParameters

    ];

  }



  if (sourceKey === 'login') {

    const geo = geoMap[String(r.ipAddress || '').trim()] || {};



    return [

      r.timestamp,

      _wwInvLoginResult_(r.eventName, r.success),

      r.eventName,

      r.ipAddress,

      geo.city || '',

      geo.region || r.subdivisionCode || '',

      geo.country || r.regionCode || '',

      geo.isp || geo.org || '',

      geo.asn || r.ipAsn || '',

      r.suspicious,

      r.challengeType,

      r.challengeStatus,

      r.loginType,

      r.failureReason,

      r.actorEmail,

      r.deviceId,

      r.client,

      r.eventType,

      r.rawParameters

    ];

  }



  if (sourceKey === 'token') {

    let raw = {};

    try {

      raw = JSON.parse(r.rawParameters || '{}');

    } catch (e) {}



    return [

      r.timestamp,

      r.eventName,

      _wwInvUseful_(raw, ['app_name', 'application_name']),

      _wwInvUseful_(raw, ['client_id']),

      _wwInvUseful_(raw, ['api_name']),

      _wwInvUseful_(raw, ['method_name']),

      _wwInvUseful_(raw, ['product_bucket', 'product']),

      _wwInvUseful_(raw, ['client_type']),

      r.ipAddress,

      r.actorEmail,

      _wwInvUseful_(raw, ['scope', 'scopes', 'oauth_scope', 'oauth_scopes', 'scope_data']),

      r.eventType,

      r.rawParameters

    ];

  }



  if (sourceKey === 'drive') {

    let raw = {};

    try {

      raw = JSON.parse(r.rawParameters || '{}');

    } catch (e) {}



    const geo = geoMap[String(r.ipAddress || '').trim()] || {};



    return [

      r.timestamp,

      r.eventName,

      _wwInvUseful_(raw, ['doc_title', 'document_title', 'item_name', 'name']),

      _wwInvUseful_(raw, ['doc_id', 'document_id', 'item_id', 'file_id']),

      r.ipAddress,

      geo.city || '',

      geo.region || r.subdivisionCode || '',

      geo.country || r.regionCode || '',

      geo.isp || geo.org || '',

      geo.asn || r.ipAsn || '',

      r.actorEmail,

      _wwInvUseful_(raw, ['owner', 'owner_email', 'owner_is_shared_drive']),

      _wwInvUseful_(raw, ['target_user', 'target_user_email', 'target_user_name']),

      _wwInvUseful_(raw, ['visibility', 'visibility_change']),

      r.eventType,

      r.rawParameters

    ];

  }



  return [

    r.timestamp,

    r.actorEmail,

    r.application,

    r.eventType,

    r.eventName,

    r.ipAddress,

    r.subdivisionCode,

    r.regionCode,

    r.ipAsn,

    r.mailEvent,

    r.subject,

    r.messageId,

    r.targetUrl,

    r.challengeType,

    r.loginType,

    r.client,

    r.sender,

    r.recipients,

    r.attachment,

    r.actionType,

    r.linkDomains,

    r.attachmentCount,

    r.success,

    r.suspicious,

    r.challengeStatus,

    r.failureReason,

    r.deviceId,

    r.rawParameters

  ];

}





/**

 * Geolocation enrichment for Login and Drive.

 * No Sheet is used.

 */

function _wwInvGetGeoMapForRows_(rows) {

  const ips = Array.from(new Set(

    (rows || [])

      .map(function(r) { return String(r.ipAddress || '').trim(); })

      .filter(function(ip) { return ip && _wwInvIsPublicIp_(ip); })

  ));



  if (!ips.length) return {};



  const out = {};

  const cache = CacheService.getScriptCache();

  const missing = [];



  ips.forEach(function(ip) {

    try {

      const cached = cache.get(WW_INVESTIGATION.GEO_CACHE_PREFIX + ip);



      if (cached) {

        const record = JSON.parse(cached);

        if (record && record.ip) out[ip] = record;

        else missing.push(ip);

      } else {

        missing.push(ip);

      }

    } catch (e) {

      missing.push(ip);

    }

  });



  missing

    .slice(0, WW_INVESTIGATION.MAX_GEO_LOOKUPS_PER_SOURCE)

    .forEach(function(ip) {

      const record = _wwInvLookupIpGeo_(ip);

      if (!record) return;



      out[ip] = record;



      try {

        cache.put(

          WW_INVESTIGATION.GEO_CACHE_PREFIX + ip,

          JSON.stringify(record),

          WW_INVESTIGATION.GEO_CACHE_SECONDS

        );

      } catch (e) {}

    });



  return out;

}





function _wwInvLookupIpGeo_(ip) {

  const providers = [

    function() { return _wwInvGeoIpWhoIs_(ip); },

    function() { return _wwInvGeoIpinfo_(ip); },

    function() { return _wwInvGeoIpapi_(ip); },

    function() { return _wwInvGeoFreeIpApi_(ip); }

  ];



  let best = null;



  for (let i = 0; i < providers.length; i++) {

    try {

      const result = providers[i]();

      if (!result) continue;



      const record = Object.assign({ ip: ip }, result);



      if ((record.city || record.region || record.country) &&

          (record.isp || record.org || record.asn)) {

        return record;

      }



      if (!best) best = record;

    } catch (e) {}

  }



  return best;

}





function _wwInvGeoIpWhoIs_(ip) {

  const res = UrlFetchApp.fetch(

    'https://ipwho.is/' + encodeURIComponent(ip),

    {

      muteHttpExceptions: true,

      headers: { Accept: 'application/json' }

    }

  );



  if (res.getResponseCode() !== 200) return null;



  const j = JSON.parse(res.getContentText() || '{}');

  if (!j || j.success === false) return null;



  const c = j.connection || {};



  return {

    city: j.city || '',

    region: j.region || '',

    country: j.country || j.country_code || '',

    isp: c.isp || c.org || '',

    org: c.org || c.isp || '',

    asn: c.asn

      ? (String(c.asn).toUpperCase().startsWith('AS') ? String(c.asn) : 'AS' + c.asn)

      : '',

    latitude: j.latitude !== undefined ? j.latitude : '',

    longitude: j.longitude !== undefined ? j.longitude : '',

    source: 'ipwho.is'

  };

}





function _wwInvGeoIpinfo_(ip) {

  const token = PropertiesService.getScriptProperties().getProperty('IPINFO_TOKEN');



  const url =

    'https://ipinfo.io/' +

    encodeURIComponent(ip) +

    '/json' +

    (token ? '?token=' + encodeURIComponent(token) : '');



  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true });



  if (res.getResponseCode() !== 200) return null;



  const j = JSON.parse(res.getContentText() || '{}');

  if (!j || !j.country) return null;



  const orgText = String(j.org || '');

  const match = orgText.match(/^(AS\d+)\s+(.+)$/i);

  const xy = String(j.loc || '').split(',');



  return {

    city: j.city || '',

    region: j.region || '',

    country: j.country || '',

    isp: match ? match[2] : (j.org || j.hostname || ''),

    org: match ? match[2] : (j.org || ''),

    asn: match ? match[1] : '',

    latitude: xy.length === 2 ? Number(xy[0]) : '',

    longitude: xy.length === 2 ? Number(xy[1]) : '',

    source: 'ipinfo.io'

  };

}





function _wwInvGeoIpapi_(ip) {

  const res = UrlFetchApp.fetch(

    'https://ipapi.co/' + encodeURIComponent(ip) + '/json/',

    {

      muteHttpExceptions: true,

      headers: { Accept: 'application/json' }

    }

  );



  if (res.getResponseCode() !== 200) return null;



  const j = JSON.parse(res.getContentText() || '{}');

  if (!j || j.error) return null;



  return {

    city: j.city || '',

    region: j.region_code || j.region || '',

    country: j.country_name || j.country || '',

    isp: j.org || '',

    org: j.org || '',

    asn: j.asn || '',

    latitude: j.latitude !== undefined ? j.latitude : '',

    longitude: j.longitude !== undefined ? j.longitude : '',

    source: 'ipapi.co'

  };

}





function _wwInvGeoFreeIpApi_(ip) {

  const res = UrlFetchApp.fetch(

    'https://free.freeipapi.com/api/v1/json/' + encodeURIComponent(ip),

    { muteHttpExceptions: true }

  );



  if (res.getResponseCode() !== 200) return null;



  const j = JSON.parse(res.getContentText() || '{}');

  if (!j || (!j.countryCode && !j.countryName)) return null;



  return {

    city: j.cityName || '',

    region: j.regionName || '',

    country: j.countryName || j.countryCode || '',

    isp: j.asnOrganization || '',

    org: j.asnOrganization || '',

    asn: j.asn

      ? (String(j.asn).toUpperCase().startsWith('AS') ? String(j.asn) : 'AS' + j.asn)

      : '',

    latitude: j.latitude !== undefined ? j.latitude : '',

    longitude: j.longitude !== undefined ? j.longitude : '',

    source: 'freeipapi.com'

  };

}





function _wwInvIsPublicIp_(ip) {

  const value = String(ip || '').trim().toLowerCase();



  if (!value) return false;



  if (value === '::1' || value === '::' || value.startsWith('fe80:')) return false;

  if (value.startsWith('fc') || value.startsWith('fd')) return false;



  const m = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);



  if (m) {

    const parts = m.slice(1).map(Number);

    if (parts.some(function(n) { return n < 0 || n > 255; })) return false;



    const a = parts[0];

    const b = parts[1];



    if (a === 10 || a === 127 || a === 0) return false;

    if (a === 169 && b === 254) return false;

    if (a === 172 && b >= 16 && b <= 31) return false;

    if (a === 192 && b === 168) return false;

    if (a === 100 && b >= 64 && b <= 127) return false;

  }



  return true;

}





function _wwInvFormatTime_(timestamp) {

  if (!timestamp) return '';



  const d = new Date(timestamp);

  if (isNaN(d.getTime())) return String(timestamp);



  const tz =

    (typeof CONFIG !== 'undefined' && CONFIG.TZ)

      ? CONFIG.TZ

      : 'America/Chicago';



  return Utilities.formatDate(d, tz, 'MM/dd/yyyy hh:mm:ss a');

}





function _wwInvFlattenParameters_(parameters, prefix, out) {

  (parameters || []).forEach(function(p) {

    if (!p || !p.name) return;



    const key = prefix ? prefix + '.' + p.name : p.name;



    if (p.value !== undefined) {

      _wwInvAddFlat_(out, key, p.value);

    } else if (p.intValue !== undefined) {

      _wwInvAddFlat_(out, key, String(p.intValue));

    } else if (p.boolValue !== undefined) {

      _wwInvAddFlat_(out, key, String(p.boolValue));

    } else if (p.multiValue !== undefined) {

      _wwInvAddFlat_(out, key, p.multiValue);

    } else if (p.multiIntValue !== undefined) {

      _wwInvAddFlat_(out, key, (p.multiIntValue || []).map(String));

    }



    if (p.messageValue && p.messageValue.parameter) {

      _wwInvFlattenParameters_(p.messageValue.parameter, key, out);

    }



    if (p.multiMessageValue && Array.isArray(p.multiMessageValue)) {

      p.multiMessageValue.forEach(function(msg, index) {

        if (!msg || !msg.parameter) return;



        _wwInvFlattenParameters_(

          msg.parameter,

          key + '[' + index + ']',

          out

        );



        _wwInvFlattenParameters_(msg.parameter, key, out);

      });

    }

  });

}





function _wwInvAddFlat_(out, key, value) {

  const normalized = Array.isArray(value)

    ? value.map(function(v) { return String(v); })

    : String(value);



  if (out[key] === undefined) {

    out[key] = normalized;

    return;

  }



  const existing = Array.isArray(out[key]) ? out[key] : [out[key]];

  const incoming = Array.isArray(normalized) ? normalized : [normalized];



  out[key] = existing.concat(incoming);

}





function _wwInvUseful_(obj, names) {

  for (let i = 0; i < names.length; i++) {

    if (

      obj[names[i]] !== undefined &&

      obj[names[i]] !== null &&

      obj[names[i]] !== ''

    ) {

      return _wwInvFlatValue_(obj[names[i]]);

    }

  }



  const keys = Object.keys(obj || {});



  for (let i = 0; i < names.length; i++) {

    const suffix = '.' + names[i].split('.').pop();



    const matches = keys.filter(function(k) {

      return k === names[i] || k.endsWith(suffix);

    });



    if (matches.length) {

      const values = [];



      matches.forEach(function(k) {

        const v = obj[k];



        if (Array.isArray(v)) {

          Array.prototype.push.apply(values, v);

        } else if (v !== undefined && v !== null && v !== '') {

          values.push(v);

        }

      });



      const unique = Array.from(

        new Set(values.map(String).filter(Boolean))

      );



      if (unique.length) return unique.join(' | ');

    }

  }



  return '';

}





function _wwInvFlatValue_(value) {

  return Array.isArray(value)

    ? Array.from(new Set(value.map(String).filter(Boolean))).join(' | ')

    : String(value);

}





function _wwInvCleanDestinations_(value) {

  if (!value) return '';



  const text = String(value);

  const emails = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi);



  if (emails && emails.length) {

    return Array.from(

      new Set(emails.map(function(v) { return v.toLowerCase(); }))

    ).join(' | ');

  }



  return text;

}





function _wwInvLoginResult_(eventName, successValue) {

  const name = String(eventName || '').toLowerCase();

  const success = String(successValue || '').toLowerCase();



  if (success === 'true') return 'SUCCESS';

  if (success === 'false') return 'FAILURE';

  if (name.indexOf('failure') >= 0 || name.indexOf('failed') >= 0) return 'FAILURE';

  if (name.indexOf('success') >= 0 || name.indexOf('login_success') >= 0) return 'SUCCESS';



  return '';

}





function _wwInvYesNo_(value) {

  const v = String(value || '').toLowerCase();



  if (v === 'true') return 'YES';

  if (v === 'false') return 'NO';



  return value || '';

}





function _wwInvGmailEventLabel_(code) {

  const labels = {

    '0': 'Unknown Gmail event (0)',

    '1': 'Message sent',

    '2': 'Message received',

    '3': 'User spam classification',

    '4': 'Gmail spam classification',

    '5': 'Message quarantined',

    '6': 'Message released from quarantine',

    '7': 'Message opened first time',

    '8': 'Message marked unread',

    '9': 'Message replied to first time',

    '10': 'Message forwarded first time',

    '11': 'Message auto-forwarded',

    '12': 'Message moved to Inbox',

    '13': 'Message moved to Trash',

    '14': 'Message removed from Trash',

    '15': 'LINK CLICKED',

    '16': 'ATTACHMENT LINK CLICKED',

    '17': 'ATTACHMENT DOWNLOADED',

    '18': 'Attachment saved to Drive',

    '19': 'Drive item saved to Drive',

    '20': 'Classification label applied',

    '21': 'Classification label changed',

    '22': 'Classification label removed',

    '23': 'Classification label applied to attachments',

    '24': 'Classification label changed on attachments',

    '25': 'Classification label removed from attachments',

    '26': 'Message archived',

    '27': 'Message permanently deleted',

    '28': 'ATTACHMENT PREVIEWED',

    '29': 'Message saved as draft',

    '30': 'Message bounced',

    '31': 'Message viewed',

    '32': 'Message downloaded',

    '33': 'Application accessed message',

    '34': 'Receive rate limited',

    '35': 'Email send initiated'

  };



  if (code === '' || code === null || code === undefined) return '';



  return labels[String(code)] || ('Unmapped Gmail event (' + code + ')');

}





/**

 * Optional manual diagnostic.

 */

function testWatchdogInvestigationLogin() {

  const end = new Date();

  const start = new Date(end.getTime() - 60 * 60 * 1000);



  Logger.log(

    JSON.stringify(

      runWatchdogInvestigationSource({

        email: Session.getActiveUser().getEmail(),

        start: start.toISOString(),

        end: end.toISOString(),

        source: 'login'

      }),

      null,

      2

    )

  );

}
