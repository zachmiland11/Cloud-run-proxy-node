import { startProxyServer, _resetProxyState } from '../cloud-run-oidc-proxy.js';
import { GoogleAuth } from 'google-auth-library';
import http from 'http';
import getPort from 'get-port';
import { promisify } from 'util';
import stream from 'stream';

const pipeline = promisify(stream.pipeline);

// Mock the google-auth-library for predictable token behavior
jest.mock('google-auth-library', () => {
  const mockFetchIdToken = jest.fn();
  const mockIdTokenProvider = {
    fetchIdToken: mockFetchIdToken,
  };
  const mockIdTokenClient = {
    idTokenProvider: mockIdTokenProvider,
  };
  const mockGoogleAuth = jest.fn(() => ({
    getIdTokenClient: jest.fn(() => Promise.resolve(mockIdTokenClient)),
  }));
  return { GoogleAuth: mockGoogleAuth, mockFetchIdToken };
});

const { mockFetchIdToken } = require('google-auth-library');

describe('Cloud Run OIDC Proxy Integration Tests', () => {
  let proxyServer;
  let proxyPort;
  let cloudRunServer;
  let cloudRunPort;
  const CLOUD_RUN_AUDIENCE = 'https://mock-cloud-run.run.app';
  const TOKEN_VALID_SECONDS = 3600; // 1 hour
  const MOCK_TOKEN_BASE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'; // Base64url encoded header

  // Helper to create a mock JWT
  const createMockJwt = (expirySeconds, aud) => {
    const expiry = Math.floor(Date.now() / 1000) + expirySeconds;
    const payload = Buffer.from(JSON.stringify({ exp: expiry, aud: aud })).toString('base64url');
    return `${MOCK_TOKEN_BASE}.${payload}.mockSignature`;
  };

  beforeAll(async () => {
    jest.useFakeTimers(); // Control time for token expiry simulation
    console.error = jest.fn(); // Suppress console.error during tests for cleaner output
  });

  afterAll(() => {
    jest.useRealTimers();
    console.error.mockRestore(); // Restore console.error
  });

  beforeEach(async () => {
    _resetProxyState(); // Reset the proxy's internal state
    mockFetchIdToken.mockClear();

    // Find available ports for mock servers
    proxyPort = await getPort();
    cloudRunPort = await getPort();

    // Setup mock Cloud Run server
    cloudRunServer = http.createServer((req, res) => {
      // Default mock Cloud Run response
      const authHeader = req.headers['authorization'] || req.headers['x-serverless-authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Unauthorized: Missing or invalid token' }));
        return;
      }

      const token = authHeader.split(' ')[1];
      // Basic check for mock token validity and audience
      try {
        const decodedPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
        if (decodedPayload.aud !== CLOUD_RUN_AUDIENCE) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: `Forbidden: Invalid audience, expected ${CLOUD_RUN_AUDIENCE}` }));
          return;
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Bad Request: Malformed token' }));
        return;
      }

      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-Cloud-Run-Path': req.url,
          'X-Cloud-Run-Method': req.method,
          'X-Cloud-Run-User-Agent': req.headers['user-agent'],
          'X-Cloud-Run-Content-Type': req.headers['content-type'],
          'Location': (req.url === '/redirect') ? `https://mock-cloud-run.run.app/new-path` : undefined // Mock redirect
        });
        res.end(JSON.stringify({
          received: {
            path: req.url,
            method: req.method,
            headers: req.headers,
            body: body ? JSON.parse(body) : undefined,
          },
          response: 'Hello from mock Cloud Run!'
        }));
      });
    });

    await new Promise(resolve => cloudRunServer.listen(cloudRunPort, '127.0.0.1', resolve));

    // Initial token setup for `getOrRefreshIdToken`
    mockFetchIdToken.mockResolvedValue(createMockJwt(TOKEN_VALID_SECONDS, CLOUD_RUN_AUDIENCE));
  });

  afterEach(async () => {
    jest.runOnlyPendingTimers();
    if (proxyServer) {
      await new Promise(resolve => proxyServer.close(resolve));
    }
    if (cloudRunServer) {
      await new Promise(resolve => cloudRunServer.close(resolve));
    }
  });

  const sendRequest = async (url, method = 'GET', headers = {}, body = null) => {
    const options = {
      method: method,
      headers: {
        'Accept': 'application/json',
        ...headers
      },
      agent: (url.startsWith('https') ? new https.Agent({ rejectUnauthorized: false }) : undefined) // For self-signed mock HTTPS if needed
    };

    if (body) {
      options.headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      options.body = JSON.stringify(body);
    }

    return new Promise((resolve, reject) => {
      const requestProtocol = url.startsWith('https') ? https : http;
      const clientReq = requestProtocol.request(url, options, (res) => {
        let rawData = '';
        res.on('data', (chunk) => { rawData += chunk; });
        res.on('end', () => {
          try {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body: JSON.parse(rawData)
            });
          } catch (e) {
            resolve({ statusCode: res.statusCode, headers: res.headers, body: rawData });
          }
        });
      });

      clientReq.on('error', (e) => reject(e));
      if (options.body) {
        clientReq.write(options.body);
      }
      clientReq.end();
    });
  };

  it('should successfully proxy a GET request with OIDC token', async () => {
    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      true, // prependUserAgent
      'Authorization' // default auth header
    );

    // Initial token fetch happens on server start, then on first request if not cached
    await Promise.resolve(); // Allow internal promises to resolve after server starts
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);

    const response = await sendRequest(`http://127.0.0.1:${proxyPort}/test-path?query=1`);

    expect(response.statusCode).toBe(200);
    expect(response.body.response).toBe('Hello from mock Cloud Run!');
    expect(response.body.received.path).toBe('/test-path?query=1');
    expect(response.body.received.method).toBe('GET');
    expect(response.body.received.headers.host).toBe(`127.0.0.1:${cloudRunPort}`);
    expect(response.body.received.headers.authorization).toMatch(/^Bearer ey/);
    expect(response.body.received.headers['user-agent']).toMatch(/^cloud-run-oidc-proxy-nodejs/);
  });

  it('should successfully proxy a POST request with a JSON body', async () => {
    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      false, // no prependUserAgent
      'X-Serverless-Authorization' // custom auth header
    );

    await Promise.resolve(); // Allow internal promises to resolve
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);

    const postBody = { message: 'Hello, Cloud Run!' };
    const response = await sendRequest(`http://127.0.0.1:${proxyPort}/submit`, 'POST', {}, postBody);

    expect(response.statusCode).toBe(200);
    expect(response.body.received.path).toBe('/submit');
    expect(response.body.received.method).toBe('POST');
    expect(response.body.received.body).toEqual(postBody);
    expect(response.body.received.headers['x-serverless-authorization']).toMatch(/^Bearer ey/);
    expect(response.body.received.headers['authorization']).toBeUndefined(); // Should not have default Authorization
    expect(response.body.received.headers['user-agent']).not.toMatch(/^cloud-run-oidc-proxy-nodejs/); // No custom user agent
    expect(response.body.received.headers['content-type']).toBe('application/json');
  });

  it('should handle Cloud Run server errors and pass them back', async () => {
    // Make mock Cloud Run return 500
    cloudRunServer.removeAllListeners('request'); // Remove previous mock handler
    cloudRunServer.on('request', (req, res) => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Cloud Run Server Error' }));
    });

    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      true,
      'Authorization'
    );
    await Promise.resolve();

    const response = await sendRequest(`http://127.0.0.1:${proxyPort}/error`);

    expect(response.statusCode).toBe(500);
    expect(response.body).toEqual({ error: 'Internal Cloud Run Server Error' });
  });

  it('should refresh the token automatically when nearing expiration', async () => {
    // First token expires in 1 minute (less than 300s buffer)
    mockFetchIdToken.mockResolvedValueOnce(createMockJwt(60, CLOUD_RUN_AUDIENCE));
    // Second token (refresh) expires in 1 hour
    mockFetchIdToken.mockResolvedValueOnce(createMockJwt(TOKEN_VALID_SECONDS, CLOUD_RUN_AUDIENCE));

    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      true,
      'Authorization'
    );
    await Promise.resolve(); // Initial token fetch

    // First request
    const response1 = await sendRequest(`http://127.0.0.1:${proxyPort}/first`);
    expect(response1.statusCode).toBe(200);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1); // Only fetched once so far

    // Advance time just enough to trigger refresh (after expiry-buffer, but before actual expiry)
    // The refresh timeout will be set to (60 - 300) * 1000 = -240000ms, clamped to 0. So it fires immediately.
    jest.advanceTimersByTime(1); // Advance a tiny bit for the 0-delay timeout to fire
    await Promise.resolve(); // Ensure promise queue is flushed for the refresh to happen

    // Second request (should use the newly refreshed token)
    const response2 = await sendRequest(`http://127.0.0.1:${proxyPort}/second`);
    expect(response2.statusCode).toBe(200);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(2); // Token should have been refreshed
  });

  it('should handle redirects by rewriting the Location header to the proxy address', async () => {
    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      true,
      'Authorization'
    );
    await Promise.resolve();

    // Make mock Cloud Run respond with a redirect
    cloudRunServer.removeAllListeners('request');
    cloudRunServer.on('request', (req, res) => {
      if (req.url === '/redirect') {
        res.writeHead(302, { 'Location': `http://127.0.0.1:${cloudRunPort}/new-path` });
        res.end();
      } else {
        res.writeHead(200);
        res.end('OK');
      }
    });

    const response = await sendRequest(`http://127.0.0.1:${proxyPort}/redirect`);

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe(`http://127.0.0.1:${proxyPort}/new-path`);
  });

  it('should return 500 if initial token fetch fails', async () => {
    mockFetchIdToken.mockRejectedValueOnce(new Error('Initial token fetch failed'));

    // We expect the startProxyServer call to throw if initial token fetch fails
    // or the first request will fail internally before even reaching mock Cloud Run
    proxyServer = startProxyServer(
      `http://127.0.0.1:${cloudRunPort}`,
      `127.0.0.1:${proxyPort}`,
      true,
      'Authorization'
    );

    // Give some time for the server to try and fetch the token on startup
    // And for the console.error to be called
    await Promise.resolve();

    const response = await sendRequest(`http://127.0.0.1:${proxyPort}/any`);

    expect(response.statusCode).toBe(500);
    expect(response.body).toEqual({
      error: {
        code: -32000,
        message: expect.stringContaining('Proxy failed to get OIDC token'),
      },
    });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('ERROR fetching OIDC token'));
  });
});
