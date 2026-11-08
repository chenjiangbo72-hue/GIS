import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cookieParser from 'cookie-parser';
import express from 'express';
import { config } from './config.js';
import {
  authenticate, createAccessToken, createRefreshToken, createUser, getUserFromAccessToken,
  revokeRefreshToken, rotateRefreshToken, safeUser
} from './auth-store.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

function validCredentials(email, password) {
  return typeof email === 'string' && /^\S+@\S+\.\S+$/.test(email) &&
    typeof password === 'string' && password.length >= 8;
}

function setRefreshCookie(res, token) {
  res.cookie(config.refreshCookie, token, {
    httpOnly: true,
    secure: config.production,
    sameSite: 'lax',
    path: '/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(config.refreshCookie, { httpOnly: true, secure: config.production, sameSite: 'lax', path: '/auth' });
}

function issueTokens(res, user, refreshToken = createRefreshToken(user)) {
  setRefreshCookie(res, refreshToken);
  return res.json({ accessToken: createAccessToken(user), user: safeUser(user) });
}

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/auth/register', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = req.body?.password;
  if (!validCredentials(email, password)) return res.status(400).json({ error: 'Use a valid email and a password of at least 8 characters.' });
  const user = await createUser(email, password);
  if (!user) return res.status(409).json({ error: 'Account already exists.' });
  return issueTokens(res, user);
});

app.post('/auth/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const user = await authenticate(email, req.body?.password || '');
  if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
  return issueTokens(res, user);
});

app.post('/auth/refresh', (req, res) => {
  try {
    const token = req.cookies[config.refreshCookie];
    if (!token) throw new Error('No refresh cookie');
    const { user, refreshToken } = rotateRefreshToken(token);
    return issueTokens(res, user, refreshToken);
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
});

app.post('/auth/logout', (req, res) => {
  revokeRefreshToken(req.cookies[config.refreshCookie]);
  clearRefreshCookie(res);
  res.status(204).end();
});

app.get('/api/me', (req, res) => {
  try {
    const header = req.get('authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw new Error('Missing bearer token');
    const user = getUserFromAccessToken(token);
    if (!user) throw new Error('Unknown user');
    return res.json({ user: safeUser(user) });
  } catch {
    return res.status(401).json({ error: 'A valid access token is required.' });
  }
});

app.listen(config.port, () => console.log(`Authentication demo running at http://localhost:${config.port}`));
