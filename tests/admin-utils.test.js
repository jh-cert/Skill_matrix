process.env.ADMIN_SESSION_SECRET = 'test-secret-for-admin-utils';
const assert = require('assert');
const { publicExportsForTests } = require('../api/admin/_utils');

const { hashPassword, verifyPassword, createSessionToken, verifySessionToken } = publicExportsForTests();

const hash = hashPassword('atbs2026', '00112233445566778899aabbccddeeff');
assert(verifyPassword('atbs2026', hash), 'password should verify');
assert(!verifyPassword('wrong', hash), 'wrong password should fail');

const token = createSessionToken('admin');
assert(verifySessionToken(token)?.u === 'admin', 'session token should verify');
assert(!verifySessionToken(token + 'x'), 'tampered token should fail');

console.log('admin utils tests passed');
