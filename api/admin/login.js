const {
  ADMIN_USERNAME,
  getAdminClient,
  verifyPassword,
  createSessionToken,
  readJson,
  methodGuard,
  sendJson,
} = require('./_utils');

module.exports = async function handler(req, res) {
  if (!methodGuard(req, res, 'POST')) return;

  try {
    const { username, password } = await readJson(req);
    if (username !== ADMIN_USERNAME || !password) {
      return sendJson(res, 401, { error: 'Invalid ID or password.' });
    }

    const db = getAdminClient();
    const { data, error } = await db
      .from('admin_credentials')
      .select('username, password_hash')
      .eq('username', ADMIN_USERNAME)
      .single();

    if (error || !data || !verifyPassword(password, data.password_hash)) {
      return sendJson(res, 401, { error: 'Invalid ID or password.' });
    }

    return sendJson(res, 200, {
      token: createSessionToken(ADMIN_USERNAME),
      username: ADMIN_USERNAME,
      expiresInSeconds: 8 * 60 * 60,
    });
  } catch (err) {
    console.error('admin login failed', err);
    return sendJson(res, err.statusCode || 500, { error: 'Login failed.' });
  }
};
