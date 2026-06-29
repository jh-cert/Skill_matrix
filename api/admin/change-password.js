const {
  ADMIN_USERNAME,
  getAdminClient,
  hashPassword,
  verifyPassword,
  readJson,
  requireAdmin,
  methodGuard,
  sendJson,
} = require('./_utils');

module.exports = async function handler(req, res) {
  if (!methodGuard(req, res, 'POST')) return;
  if (!(await requireAdmin(req, res))) return;

  try {
    const { currentPassword, newPassword } = await readJson(req);
    if (!currentPassword || !newPassword || String(newPassword).length < 8) {
      return sendJson(res, 400, { error: 'Current password and a new password of at least 8 characters are required.' });
    }

    const db = getAdminClient();
    const { data, error } = await db
      .from('admin_credentials')
      .select('password_hash')
      .eq('username', ADMIN_USERNAME)
      .single();

    if (error || !data || !verifyPassword(currentPassword, data.password_hash)) {
      return sendJson(res, 401, { error: 'Current password is incorrect.' });
    }

    const { error: updateError } = await db
      .from('admin_credentials')
      .update({ password_hash: hashPassword(newPassword), updated_at: new Date().toISOString() })
      .eq('username', ADMIN_USERNAME);

    if (updateError) throw updateError;
    return sendJson(res, 200, { ok: true });
  } catch (err) {
    console.error('password change failed', err);
    return sendJson(res, err.statusCode || 500, { error: 'Password change failed.' });
  }
};
