/* global AdminReports, AdminDirectory */
/**
 * Archive.gs — Archive sheet pruning: by age, by row count, or both (smart).
 *               Includes a nightly trigger helper.
 */

function pruneArchiveByDays(keepDays) {
  _pruneArchive_({ keepDays: Number(keepDays) || 90, maxRows: null });
}

function pruneArchiveByMaxRows(maxRows) {
  _pruneArchive_({ keepDays: null, maxRows: Number(maxRows) || 20000 });
}

function pruneArchiveSmart(keepDays, maxRows) {
  _pruneArchive_({
    keepDays: (keepDays === undefined ? 90 : Number(keepDays) || 90),
    maxRows:  (maxRows  === undefined ? 20000 : Number(maxRows) || 20000)
  });
}

function addArchivePruneTrigger() {
  try {
    ScriptApp.getProjectTriggers().forEach(t => {
      if (t.getHandlerFunction && t.getHandlerFunction() === 'pruneArchiveSmart') {
        ScriptApp.deleteTrigger(t);
      }
    });
  } catch (e) {}
  ScriptApp.newTrigger('pruneArchiveSmart').timeBased().atHour(1).everyDays(1).create();
}

function _pruneArchive_(opts) {
  const t0 = new Date();
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName(CONFIG.ARCHIVE);
  if (!sh) return;

  const header = sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0] || [];
  if (!header.length) return;

  const rows = _getRows(sh);
  if (!rows.length) return;

  const items = rows.map(r => {
    const ts = new Date(r[0]);
    return { ts: isNaN(ts) ? null : ts, row: r };
  });

  items.sort((a,b) => {
    if (!a.ts && !b.ts) return 0;
    if (!a.ts) return 1;
    if (!b.ts) return -1;
    return b.ts - a.ts;
  });

  let kept = items;

  if (opts.keepDays && opts.keepDays > 0) {
    const cutoff = new Date(Date.now() - opts.keepDays * 24 * 3600000);
    kept = kept.filter(x => !x.ts || x.ts >= cutoff);
  }

  if (opts.maxRows && opts.maxRows > 0 && kept.length > opts.maxRows) {
    kept = kept.slice(0, opts.maxRows);
  }

  if (kept.length === rows.length) {
    _logDiagnostics('_pruneArchive_/noop', t0, new Date(), 0, kept.length, 'No change. Rows=' + kept.length);
    return;
  }

  _clearBody(sh);
  if (kept.length) sh.getRange(2,1,kept.length, sh.getLastColumn()).setValues(kept.map(x => x.row));

  const keyIdx = header.indexOf('Event Key');
  if (keyIdx >= 0) _dedupeSheetByKey(sh, header, keyIdx);

  _logDiagnostics('_pruneArchive_', t0, new Date(), 0, kept.length,
    'Pruned to rows=' + kept.length +
    (opts.keepDays ? (', keepDays=' + opts.keepDays) : '') +
    (opts.maxRows ? (', maxRows=' + opts.maxRows) : ''));
}
