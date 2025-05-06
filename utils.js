// utils.js


export function parseCookies(cookieHeader) {
    if (!cookieHeader) return {};
    return cookieHeader.split(';').reduce((acc, cookie) => {
      const [name, ...rest] = cookie.trim().split('=');
      acc[name] = rest.join('=');
      return acc;
    }, {});
  }
  
  

  export function handleOptions(request , env) {
    const headers = request.headers;
    const origin = headers.get('Origin');
    if (
      origin !== null &&
      headers.get('Access-Control-Request-Method') !== null &&
      headers.get('Access-Control-Request-Headers') !== null
    ) {
      // Handle CORS preflight request
      const allowedOrigins = env.YOUR_DOMAIN.split(',');
      const respHeaders = {
        'Access-Control-Allow-Origin': allowedOrigins.includes(origin) ? origin : '',
        'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
        'Access-Control-Allow-Headers': headers.get('Access-Control-Request-Headers'),
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400', // Cache preflight response for 1 day
      };
      return new Response(null, { status: 204, headers: respHeaders });
    } else {
      // Handle standard OPTIONS request
      return new Response(null, {
        headers: {
          Allow: 'GET, PUT, POST, OPTIONS',
        },
      });
    }
  }
  export function createResponse(body, options = {}, request, env) {
    const response = new Response(body, options);
    const origin = request.headers.get('Origin');
    const allowedOrigins = env.YOUR_DOMAIN.split(',');
  
    if (allowedOrigins.includes(origin) ) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }
    return response;
  }
  
  export async function writeData(setCache, request, env) {
    const url = new URL(request.url);
    const key = url.searchParams.get('key');
    if (!key) {
      // return new Response('Key parameter is missing', { status: 400 });
      return createResponse('Key parameter is missing', { status: 400 }, request, env);
    }

    const body = await request.text();
    try {
      const jsonData = JSON.parse(body);
      await setCache(key, JSON.stringify(jsonData));
      // return new Response('Data stored successfully', { status: 200 });
      return createResponse('Data stored successfully', { status: 200 }, request, env);
    } catch (err) {
      // return new Response('Invalid JSON data', { status: 400 });
      return createResponse('Invalid JSON data', { status: 400 }, request, env);
    }
  }
