const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://vksjvsckahmrzhqqplfv.supabase.co';
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET;
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const ADMIN_USERNAME = 'admin';
const PBKDF2_ITERATIONS = 210000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';

function requireSessionSecret() {
  if (!SESSION_SECRET) throw Object.assign(new Error('Missing ADMIN_SESSION_SECRET'), { statusCode: 500 });
}

function requireEnv() {
  if (!SERVICE_ROLE_KEY) throw Object.assign(new Error('Missing SUPABASE_SERVICE_ROLE_KEY'), { statusCode: 500 });
  requireSessionSecret();
}

function getAdminClient() {
  requireEnv();
  return createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

function timingSafeEqualText(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.pbkdf2Sync(String(password), salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = Number(parts[1]);
  const salt = parts[2];
  const expected = parts[3];
  if (!Number.isInteger(iterations) || !salt || !expected) return false;
  const actual = crypto.pbkdf2Sync(String(password), salt, iterations, Buffer.from(expected, 'hex').length, PBKDF2_DIGEST).toString('hex');
  return timingSafeEqualText(actual, expected);
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signPayload(payloadB64) {
  requireSessionSecret();
  return crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest('base64url');
}

function createSessionToken(username = ADMIN_USERNAME) {
  const payload = {
    u: username,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const payloadB64 = base64url(JSON.stringify(payload));
  return `${payloadB64}.${signPayload(payloadB64)}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payloadB64, sig] = token.split('.');
  const expected = signPayload(payloadB64);
  if (!timingSafeEqualText(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (payload.u !== ADMIN_USERNAME) return null;
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.trim()) return JSON.parse(req.body);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function getBearerToken(req) {
  const header = req.headers.authorization || req.headers.Authorization || '';
  const m = String(header).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function requireAdmin(req, res) {
  const token = getBearerToken(req);
  const payload = verifySessionToken(token);
  if (!payload) {
    sendJson(res, 401, { error: 'Admin login required.' });
    return null;
  }
  return payload;
}

function methodGuard(req, res, method) {
  if (req.method === method) return true;
  res.setHeader('Allow', method);
  sendJson(res, 405, { error: `Method ${req.method} not allowed.` });
  return false;
}

function publicExportsForTests() {
  return { hashPassword, verifyPassword, createSessionToken, verifySessionToken };
}

module.exports = {
  ADMIN_USERNAME,
  getAdminClient,
  hashPassword,
  verifyPassword,
  createSessionToken,
  readJson,
  requireAdmin,
  methodGuard,
  sendJson,
  publicExportsForTests,
};
