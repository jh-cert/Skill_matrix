const {
  getAdminClient,
  readJson,
  requireAdmin,
  methodGuard,
  sendJson,
} = require('./_utils');

const BATCH = 50;
const ZERO_UUID = '00000000-0000-0000-0000-000000000000';

function requireArray(value, name) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array.`);
}

function validateParsed(parsed) {
  if (!parsed || typeof parsed !== 'object') throw new Error('Invalid upload payload.');
  requireArray(parsed.persons, 'persons');
  requireArray(parsed.regs, 'regs');
  requireArray(parsed.levels, 'levels');
  requireArray(parsed.history, 'history');
  if (parsed.persons.length === 0) throw new Error('No persons found in Excel file.');
  if (parsed.regs.length === 0) throw new Error('No regulations found in Excel file.');
}

module.exports = async function handler(req, res) {
  if (!methodGuard(req, res, 'POST')) return;
  if (!(await requireAdmin(req, res))) return;

  try {
    const { parsed, version } = await readJson(req);
    validateParsed(parsed);
    const db = getAdminClient();

    const { data: personRows, error: pErr } = await db
      .from('persons')
      .upsert(parsed.persons.map((name) => ({ name })), { onConflict: 'name' })
      .select('id, name');
    if (pErr) throw new Error('persons: ' + pErr.message);

    const nameToId = {};
    personRows.forEach((p) => { nameToId[p.name] = p.id; });

    const keepNames = parsed.persons;
    const { data: allDbPersons, error: allPersonsErr } = await db.from('persons').select('id, name');
    if (allPersonsErr) throw new Error('persons list: ' + allPersonsErr.message);
    const toDelete = (allDbPersons || []).filter((p) => !keepNames.includes(p.name));
    for (const person of toDelete) {
      const { error: delErr } = await db.from('persons').delete().eq('id', person.id);
      if (delErr) throw new Error(`delete person ${person.name}: ${delErr.message}`);
      delete nameToId[person.name];
    }

    const regUpsertData = parsed.regs.map((r) => ({
      vehicle_type: r.vtype,
      row_index: r.row_index,
      subject: r.subject,
      regulatory_act: r.regulatory_act,
      un_regulation: r.un_regulation,
    }));
    const keyToId = {};
    for (let i = 0; i < regUpsertData.length; i += BATCH) {
      const { data: regRows, error: rErr } = await db
        .from('regulations')
        .upsert(regUpsertData.slice(i, i + BATCH), { onConflict: 'vehicle_type,row_index' })
        .select('id, vehicle_type, row_index');
      if (rErr) throw new Error('regulations: ' + rErr.message);
      regRows.forEach((r) => { keyToId[`${r.vehicle_type}|${r.row_index}`] = r.id; });
    }

    const { error: lvlDeleteErr } = await db.from('skill_levels').delete().neq('id', ZERO_UUID);
    if (lvlDeleteErr) throw new Error('delete skill_levels: ' + lvlDeleteErr.message);

    const lvlData = parsed.levels
      .filter((l) => nameToId[l.person] && keyToId[l.regKey])
      .map((l) => ({
        person_id: nameToId[l.person],
        regulation_id: keyToId[l.regKey],
        current_level: l.level,
      }));
    for (let i = 0; i < lvlData.length; i += BATCH) {
      const { error: lErr } = await db.from('skill_levels').insert(lvlData.slice(i, i + BATCH));
      if (lErr) throw new Error('skill_levels: ' + lErr.message);
    }

    const { error: histDeleteErr } = await db.from('skill_history').delete().gte('created_at', '1900-01-01');
    if (histDeleteErr) throw new Error('delete skill_history: ' + histDeleteErr.message);

    const histData = parsed.history
      .filter((h) => nameToId[h.person] && keyToId[h.regKey])
      .map((h) => ({
        person_id: nameToId[h.person],
        regulation_id: keyToId[h.regKey],
        level: h.level,
        acquired_date: h.acquired_date,
        test_report_number: h.test_report_number,
      }));
    for (let i = 0; i < histData.length; i += BATCH) {
      const { error: hErr } = await db.from('skill_history').insert(histData.slice(i, i + BATCH));
      if (hErr) throw new Error('skill_history: ' + hErr.message);
    }

    return sendJson(res, 200, {
      ok: true,
      version: version || null,
      counts: {
        persons: parsed.persons.length,
        removedPersons: toDelete.length,
        regulations: parsed.regs.length,
        skillLevels: lvlData.length,
        history: histData.length,
      },
    });
  } catch (err) {
    console.error('admin upload failed', err);
    return sendJson(res, err.statusCode || 400, { error: err.message || 'Upload failed.' });
  }
};
