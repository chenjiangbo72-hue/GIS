import { createHash, randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from './config.js';

const usersByEmail = new Map();
const usersById = new Map();
const refreshSessions = new Map();

const digest = (value) => createHash('sha256').update(value).digest('hex');

export async function createUser(email, password) {
  if (usersByEmail.has(email)) return null;
  const user = { id: randomUUID(), email, passwordHash: await bcrypt.hash(password, 12) };
  usersByEmail.set(email, user);
  usersById.set(user.id, user);
  return safeUser(user);
}

export async function authenticate(email, password) {
  const user = usersByEmail.get(email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return null;
  return user;
}

export function safeUser(user) {
  return { id: user.id, email: user.email };
}

export function createAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, type: 'access' }, config.accessSecret, {
    expiresIn: config.accessTtl
  });
}

export function createRefreshToken(user) {
  const jti = randomUUID();
  const token = jwt.sign({ sub: user.id, type: 'refresh', jti }, config.refreshSecret, {
    expiresIn: config.refreshTtl
  });
  // Store only a one-way digest. The browser remains the sole holder of the raw token.
  refreshSessions.set(jti, { userId: user.id, tokenDigest: digest(token) });
  return token;
}

export function rotateRefreshToken(token) {
  const payload = jwt.verify(token, config.refreshSecret);
  if (payload.type !== 'refresh' || !payload.jti) throw new Error('Invalid refresh token');

  const session = refreshSessions.get(payload.jti);
  // Consume the token before issuing a replacement: replay of a stolen old token fails.
  refreshSessions.delete(payload.jti);
  if (!session || session.userId !== payload.sub || session.tokenDigest !== digest(token)) {
    throw new Error('Refresh token revoked or unknown');
  }

  const user = usersById.get(payload.sub);
  if (!user) throw new Error('User no longer exists');
  return { user, refreshToken: createRefreshToken(user) };
}

export function revokeRefreshToken(token) {
  try {
    const payload = jwt.verify(token, config.refreshSecret);
    if (payload.jti) refreshSessions.delete(payload.jti);
  } catch {
    // Logout is idempotent; invalid or expired cookies are simply cleared.
  }
}

export function getUserFromAccessToken(token) {
  const payload = jwt.verify(token, config.accessSecret);
  if (payload.type !== 'access') throw new Error('Invalid access token');
  return usersById.get(payload.sub) || null;
}
