import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const {
  PORT = 8080,
  CLIENT_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  JWT_SECRET,
  COOKIE_NAME = 'animorex_session'
} = process.env;

app.use(cors({ origin: CLIENT_URL, credentials: true }));

function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true, // Render is HTTPS
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}

function readSession(req) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// -------- Discord OAuth --------
app.get('/api/auth/discord/login', (_req, res) => {
  const scope = encodeURIComponent('identify email');
  const url =
    `https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
    `&response_type=code&scope=${scope}`;
  res.redirect(url);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect(`${CLIENT_URL}/?auth=error`);
  try {
    const body = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI
    });
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) return res.redirect(`${CLIENT_URL}/?auth=error`);

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const user = await userRes.json();
    if (!userRes.ok) return res.redirect(`${CLIENT_URL}/?auth=error`);

    const sessionPayload = {
      provider: 'discord',
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      avatar: user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`
        : `https://cdn.discordapp.com/embed/avatars/0.png`,
      email: null
    };
    setSessionCookie(res, sessionPayload);
    res.redirect(`${CLIENT_URL}/?auth=success`);
  } catch (e) {
    console.error('Discord error:', e);
    res.redirect(`${CLIENT_URL}/?auth=error`);
  }
});

// -------- Google OAuth --------
app.get('/api/auth/google/login', (_req, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    include_granted_scopes: 'true',
    prompt: 'consent'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.redirect(`${CLIENT_URL}/?auth=error`);
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: GOOGLE_REDIRECT_URI
      })
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) return res.redirect(`${CLIENT_URL}/?auth=error`);

    const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const profile = await userRes.json();
    if (!userRes.ok) return res.redirect(`${CLIENT_URL}/?auth=error`);

    const sessionPayload = {
      provider: 'google',
      id: profile.sub,
      username: profile.name || profile.given_name || 'User',
      global_name: profile.name || null,
      avatar: profile.picture || null,
      email: profile.email || null
    };
    setSessionCookie(res, sessionPayload);
    res.redirect(`${CLIENT_URL}/?auth=success`);
  } catch (e) {
    console.error('Google error:', e);
    res.redirect(`${CLIENT_URL}/?auth=error`);
  }
});

// -------- Common session routes --------
app.get('/api/me', (req, res) => {
  const sess = readSession(req);
  if (!sess) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: sess });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

app.get('/', (_req, res) => res.send('Animorex Auth API (Discord + Google) running'));

app.listen(PORT, () => console.log(`Auth server on ${PORT}`));
