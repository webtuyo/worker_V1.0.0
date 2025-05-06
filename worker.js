// worker.js
import { handleOptions, createResponse, writeData, parseCookies } from "./utils.js";
import { authenticateUser } from './auth.js';
import { verifySessionToken, storeSessionToken, generateSessionToken, getSessionsLog, getRateLimit } from './database.js';
import { SESSION_DURATION } from './config.js'; // Import the session duration from config.js


export default {
  async fetch(request, env) {
    const setCache = (key, data) => env.WEBTUYOKV.put(key, data);
    const getCache = (key) => env.WEBTUYOKV.get(key);

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return handleOptions(request, env);
    }

    // --- Helper function to get allowed origins ---
    const getAllowedOrigins = () => {
      // Ensure YOUR_DOMAIN exists and is a string before splitting
      return env.YOUR_DOMAIN && typeof env.YOUR_DOMAIN === 'string' ? env.YOUR_DOMAIN.split(',') : [];
    };

    // --- Helper function to check if origin is allowed ---
    const isOriginAllowed = (request) => {
      const origin = request.headers.get('Origin');
      const allowedOrigins = getAllowedOrigins();
      // Check if origin exists and is included in the allowed list
      return origin && allowedOrigins.includes(origin);
    };
    // -----------------------------------------------


    //GET value from KV (Authenticating not required)
    if (request.method === 'GET' && new URL(request.url).pathname === '/') { // Assuming GET for KV is at the root path now or specific path check needed
        let key = new URL(request.url).searchParams.get('key');
        if (!key) {
          key = 'live'; // Default key
        }
        const cache = await getCache(key);
        // Use isOriginAllowed check also for simple GET if needed, though createResponse handles basic CORS headers
        return createResponse(cache || 'No data found', {
          status: cache ? 200 : 404,
        }, request, env);
    }


    //GET Sessions Logs from DB (Authenticating required)
    if (request.method === 'GET' && new URL(request.url).pathname === '/sessionslog') {
      const sessionIsValid = await verifySessionToken(env, request);
      if (!sessionIsValid) {
        return createResponse('Unauthorized', { status: 401 }, request, env);
      }
      const logs = await getSessionsLog(env);
      return createResponse(JSON.stringify(logs), {
        headers: {
          'Content-Type': 'application/json',
        },
      }, request, env);
    }

    //GET Rate_Limit from DB (Authenticating required)
    if (request.method === 'GET' && new URL(request.url).pathname === '/rate_limit') {
      const sessionIsValid = await verifySessionToken(env, request);
      if (!sessionIsValid) {
        return createResponse('Unauthorized', { status: 401 }, request, env);
      }
      const rateLimit = await getRateLimit(env);
      return createResponse(JSON.stringify(rateLimit), {
        headers: {
          'Content-Type': 'application/json',
        },
      }, request, env);
    }

    // Ensure the request is over HTTPS
    const url = new URL(request.url);
    // Note: Cloudflare automatically redirects HTTP to HTTPS for proxied sites,
    // but this check is still good practice if the worker might be hit directly.
    if (url.protocol !== 'https:') {
         // Let createResponse handle CORS headers even for this error
        return createResponse('HTTPS is required', { status: 400 }, request, env);
    }

    if (request.method === 'PUT') {
      // First, check if the user already has a valid session
      const sessionIsValid = await verifySessionToken(env, request);
      if (sessionIsValid) {
        // If already logged in, just allow writing data.
        // createResponse will add necessary CORS headers if origin is allowed.
        return await writeData(setCache, request, env);
      }

      // If no valid session, authenticate with OTP and password
      const authResponse = await authenticateUser(env, request);
      if (authResponse) {
        // Authentication failed, return the error response (createResponse used inside auth.js handles CORS)
        return authResponse;
      }

      // --- Authentication Successful ---

      // Generate a new session token
      const sessionToken = generateSessionToken();
      const expirationTimestamp = Math.floor(Date.now() / 1000) + SESSION_DURATION;
      const ip =
        request.headers.get('CF-Connecting-IP') ||
        request.headers.get('X-Forwarded-For') ||
        '0.0.0.0';

      await storeSessionToken(env, sessionToken, expirationTimestamp, ip);

      // Write the data the user intended to PUT
      const response = await writeData(setCache, request, env);

      // *** Conditionally set SameSite attribute for the new session cookie ***
      let cookieString = `session_token=${sessionToken}; HttpOnly; Secure; Max-Age=${SESSION_DURATION}`;
      if (isOriginAllowed(request)) {
          // If the origin is in the allowed list, use SameSite=None for cross-domain access
          cookieString += '; SameSite=None';
      } else {
          // Otherwise, use the more restrictive SameSite=Strict (default browser behavior often)
          cookieString += '; SameSite=Strict';
      }
      response.headers.append('Set-Cookie', cookieString);
      // -----------------------------------------------------------------------

      return response; // Return the response from writeData with the added cookie
    }

    if (request.method === 'POST' && url.pathname === '/logout') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const sessionToken = cookies['session_token'];

      if (sessionToken) {
        // Delete the session from the DB
        await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`)
          .bind(sessionToken)
          .run();
      }

      // Create the base logout response
      const response = createResponse('Logged out', { status: 200 }, request, env);

      // *** Conditionally set SameSite attribute for the expiring cookie ***
      let cookieString = `session_token=; HttpOnly; Secure; Max-Age=0`;
      if (isOriginAllowed(request)) {
        // If the origin is in the allowed list, use SameSite=None
        cookieString += '; SameSite=None';
      } else {
        // Otherwise, use SameSite=Strict
        cookieString += '; SameSite=Strict';
      }
      response.headers.append('Set-Cookie', cookieString);
      // --------------------------------------------------------------------

      return response;
    }

    // Fallback for unhandled methods/paths
    return createResponse('Method not allowed or path not found', { status: 405 }, request, env);
  },
};
