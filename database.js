import { MAX_ATTEMPTS, BLOCK_DURATION } from "./config.js"; 
import { parseCookies } from "./utils.js";



export async function ensureTableSessionsExists(env) {
  // Check if the 'sessionslog' table exists
  const tableCheck = await env.DB.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='sessionslog'
  `).first();

  // If the table doesn't exist, create it
  if (!tableCheck) {
      await env.DB.prepare(`
          CREATE TABLE sessionslog (
              timelogin TEXT PRIMARY KEY,
              expires_at INTEGER NOT NULL,
              ip TEXT NOT NULL
          )
      `).run();
  }

  // Repeat the same process for 'sessions' table if necessary
  const sessionsTableCheck = await env.DB.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'
  `).first();

  if (!sessionsTableCheck) {
      await env.DB.prepare(`
          CREATE TABLE sessions (
              token TEXT PRIMARY KEY,
              expires_at INTEGER NOT NULL
          )
      `).run();
  }
}

export async function ensureTableRateLimitExists(env) {
  // Check if the 'rate_limit' table exists
  const tableCheck = await env.DB.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='rate_limit'
  `).first();

  // If the table doesn't exist, create it
  if (!tableCheck) {
      await env.DB.prepare(`
          CREATE TABLE rate_limit (
              ip_address TEXT PRIMARY KEY,
              attempts INTEGER NOT NULL DEFAULT 1,
              blocked_until INTEGER
          )
      `).run();
  }
}


 // Helper function for rate limiting g
 export async function isBlocked(env, ip) {
    const now = Math.floor(Date.now() / 1000); // Current time in seconds
    const result = await env.DB.prepare(
      `SELECT attempts, blocked_until FROM rate_limit WHERE ip_address = ?`
    )
      .bind(ip)
      .first();

    if (result) {
      const { attempts, blocked_until } = result;
      if (blocked_until && blocked_until > now) {
        // IP is currently blocked
        return true;
      }

      if (blocked_until && blocked_until <= now) {
        // Block duration has expired; reset attempts
        await resetAttempts(ip);
        return false;
      }
    }

    return false;
  }

export async function incrementAttempts(env, ip) {
    const now = Math.floor(Date.now() / 1000); // Current time in seconds
    const result = await env.DB.prepare(
    `SELECT attempts FROM rate_limit WHERE ip_address = ?`
    )
    .bind(ip)
    .first();

    let attempts = 1;
    if (result) {
    attempts = result.attempts + 1;
    }

    if (attempts >= MAX_ATTEMPTS) {
    const blocked_until = now + BLOCK_DURATION;
    await env.DB.prepare(
        `INSERT INTO rate_limit (ip_address, attempts, blocked_until)
        VALUES (?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET attempts = excluded.attempts, blocked_until = excluded.blocked_until`
    )
        .bind(ip, attempts, blocked_until)
        .run();
      
    } else {
    await env.DB.prepare(
        `INSERT INTO rate_limit (ip_address, attempts, blocked_until)
        VALUES (?, ?, NULL)
        ON CONFLICT(ip_address) DO UPDATE SET attempts = excluded.attempts`
    )
        .bind(ip, attempts)
        .run();
    }

    // Cleanup the rate_limit table, keeping only the last 250 rows
    await env.DB.prepare(`
      DELETE FROM rate_limit
      WHERE rowid NOT IN (SELECT rowid FROM rate_limit ORDER BY rowid DESC LIMIT 250)
    `).run();

}

export async function resetAttempts(env, ip) {
    await env.DB.prepare(
    `DELETE FROM rate_limit WHERE ip_address = ?`
    )
    .bind(ip)
    .run();
}

// Store session token in D1 DB
export async function storeSessionToken(env, token, expirationTimestamp, ip) {
    // Ensure you have a 'sessions' table in your D1 DB with 'token' and 'expires_at' columns
    await env.DB.prepare(
        `INSERT INTO sessions (token, expires_at)
        VALUES (?, ?)`
    )
        .bind(token, expirationTimestamp)
        .run();
    let timeLogin = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO sessionslog (timelogin, expires_at, ip)
      VALUES (?, ?, ?)`
    )
      .bind(timeLogin, expirationTimestamp, ip)
      .run();

    // Cleanup the sessions table, keeping only the last 250 rows
    await env.DB.prepare(`
      DELETE FROM sessions 
      WHERE rowid NOT IN (SELECT rowid FROM sessions ORDER BY rowid DESC LIMIT 250)
    `)
    .run();

    // Cleanup the sessionslog table, keeping only the last 250 rows
    await env.DB.prepare(`
      DELETE FROM sessionslog
      WHERE rowid NOT IN (SELECT rowid FROM sessionslog ORDER BY rowid DESC LIMIT 250)
    `)
    .run();
}

  // Generate a secure session token
  export function generateSessionToken() {
    return crypto.randomUUID();
  }
  

// Check if session token is valid
export async function verifySessionToken(env, request) {
    const cookieHeader = request.headers.get('Cookie');
    const cookies = parseCookies(cookieHeader);
    const sessionToken = cookies['session_token'];
    await ensureTableSessionsExists(env);
    await ensureTableRateLimitExists(env);

    if (!sessionToken) {
    return false;
    }

    const now = Math.floor(Date.now() / 1000); // Current time in seconds
    const result = await env.DB.prepare(
    `SELECT * FROM sessions WHERE token = ? AND expires_at > ?`
    )
    .bind(sessionToken, now)
    .first();

    if (!result) {
    return false;
    }

    // Optionally, extend the session expiration time here if needed
    return true;
}

export async function getSessionsLog(env) {
  const sessions = await env.DB.prepare(
    `SELECT * FROM sessionslog`
  ).all();
  return sessions;
}

export async function getRateLimit(env) {
  const rateLimit = await env.DB.prepare(
    `SELECT * FROM rate_limit`
  ).all();
  return rateLimit;
}
