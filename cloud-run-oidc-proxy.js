// Copyright 2025 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { GoogleAuth } from 'google-auth-library';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import process from 'process';

// Global variables for authentication and token management
let idTokenClient = null;
let cachedIdToken = null;
let tokenRefreshTimeout = null;

const TOKEN_REFRESH_BUFFER_SECONDS = 300; // Refresh token 5 minutes before it expires
const DEFAULT_BIND_ADDRESS = '127.0.0.1:8080';
const USER_AGENT_BASE = 'cloud-run-oidc-proxy-nodejs';
const VERSION = '1.0.0'; // Example version, ideally would be dynamic
const OS_ARCH = `${process.platform}/${process.arch}`;
const DEFAULT_AUTHORIZATION_HEADER = 'X-Serverless-Authorization'; // Matching Go's default

/**
 * Fetches an OIDC identity token for the given audience.
 * Caches the token and schedules its refresh.
 * @param {string} audience - The target URL for which the token is being requested.
 * @returns {Promise<string>} The OIDC identity token.
 */
export async function getOrRefreshIdToken(audience) {
  if (!idTokenClient) {
    const auth = new GoogleAuth();
    idTokenClient = await auth.getIdTokenClient(audience);
  }

  // If a token is already cached and valid for a reasonable time, return it
  if (cachedIdToken) {
    const decodedToken = decodeJwt(cachedIdToken);
    const expiryTimeMs = decodedToken.exp * 1000;
    if (expiryTimeMs > Date.now() + (TOKEN_REFRESH_BUFFER_SECONDS * 1000)) {
      // Token is still valid for more than the buffer time
      return cachedIdToken;
    }
  }

  // Fetch a new token
  try {
    // idTokenProvider.fetchIdToken directly returns the token string
    const newTokenResponse = await idTokenClient.idTokenProvider.fetchIdToken(audience);
    cachedIdToken = newTokenResponse;
    // Log success. This will be captured by Jest's spy in tests.
    console.error(`CloudRunOIDCProxy: Successfully fetched new OIDC token.`);

    // Decode the token to get its expiration time and schedule a refresh
    const decodedToken = decodeJwt(cachedIdToken);
    const expiresInSeconds = decodedToken.exp - (Date.now() / 1000);

    if (tokenRefreshTimeout) {
      clearTimeout(tokenRefreshTimeout);
    }

    const refreshDelayMs = Math.max(0, (expiresInSeconds - TOKEN_REFRESH_BUFFER_SECONDS) * 1000);
    tokenRefreshTimeout = setTimeout(async () => {
      // Log refresh attempt. This will be captured by Jest's spy in tests.
      console.error('CloudRunOIDCProxy: OIDC token nearing expiration, refreshing...');
      try {
        await getOrRefreshIdToken(audience);
      } catch (refreshError) {
        // Log refresh error. This will be captured by Jest's spy in tests.
        console.error(`CloudRunOIDCProxy: ERROR refreshing OIDC token: ${refreshError.message}`);
        // Consider a retry mechanism or more robust error handling here for refresh failures
      }
    }, refreshDelayMs);

    return cachedIdToken;
  } catch (error) {
    // Log initial fetch error. This will be captured by Jest's spy in tests.
    console.error(`CloudRunOIDCProxy: ERROR fetching OIDC token: ${error.message}`);
    console.error(`CloudRunOIDCProxy: Please ensure your local 'gcloud' credentials are set up via 'gcloud auth application-default login',`);
    console.error(`CloudRunOIDCProxy: or that the environment variable GOOGLE_APPLICATION_CREDENTIALS points to a valid service account key.`);
    throw error; // Propagate error so main can decide to exit
  }
}

/**
 * Decodes a JWT token to extract its payload.
 * @param {string} token - The JWT token string.
 * @returns {object} The decoded JWT payload.
 */
export function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    return payload;
  } catch (error) {
    // Log decoding error. This will be captured by Jest's spy in tests.
    console.error(`CloudRunOIDCProxy: Error decoding JWT: ${error.message}`);
    throw error;
  }
}

/**
 * Resets the internal state for testing purposes.
 * @private
 */
export function _resetProxyState() {
  idTokenClient = null;
  cachedIdToken = null;
  if (tokenRefreshTimeout) {
    clearTimeout(tokenRefreshTimeout);
    tokenRefreshTimeout = null;
  }
}

/**
 * Starts the HTTP proxy server.
 * @param {string} targetUrl - The Cloud Run service URL to proxy requests to.
 * @param {string} bindAddress - The local host:port to listen on.
 * @param {boolean} prependUserAgent - Whether to prepend a custom User-Agent header.
 * @param {string} authorizationHeaderName - The name of the authorization header to use.
 * @returns {http.Server} The started HTTP server instance.
 */
export function startProxyServer(targetUrl, bindAddress, prependUserAgent, authorizationHeaderName) {
  const parsedTargetUrl = new URL(targetUrl);
  const proxyProtocol = parsedTargetUrl.protocol === 'https:' ? https : http;

  const userAgent = `${USER_AGENT_BASE}/${VERSION} (${OS_ARCH})`;

  const server = http.createServer(async (req, res) => {
    let idToken;
    try {
      idToken = await getOrRefreshIdToken(targetUrl);
    } catch (error) {
      // Error already logged by getOrRefreshIdToken (and captured by Jest spy)
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: {
          code: -32000,
          message: `Proxy failed to get OIDC token: ${error.message}`,
        },
      }));
      return;
    }

    const requestBodyChunks = [];
    req.on('data', (chunk) => {
      requestBodyChunks.push(chunk);
    });

    req.on('end', () => {
      const incomingBody = Buffer.concat(requestBodyChunks);

      const headers = {
        'Authorization': `Bearer ${idToken}`,
        'Host': parsedTargetUrl.host, // Crucial for Cloud Run
        // Copy most headers from the incoming request, but allow overrides
      };

      // Copy all original headers, giving precedence to proxy-set headers
      for (const key in req.headers) {
        if (!headers[key] && key !== 'host' && key !== 'authorization') { // Avoid duplicating host/auth
          headers[key] = req.headers[key];
        }
      }

      // Handle Content-Type for POST/PUT requests
      if (req.headers['content-type']) {
        headers['Content-Type'] = req.headers['content-type'];
      } else if (incomingBody.length > 0) {
        // If there's a body but no content-type, default to application/octet-stream
        // or a more appropriate default if the application is known to send JSON.
        // For simplicity, we'll assume JSON if a body is present and not explicitly set.
        // You might want to remove this if you expect other binary data.
        headers['Content-Type'] = 'application/json';
      }

      // Prepend User-Agent if enabled
      if (prependUserAgent) {
        const originalUserAgent = headers['user-agent'];
        if (originalUserAgent) {
          headers['User-Agent'] = `${userAgent} ${originalUserAgent}`;
        } else {
          headers['User-Agent'] = userAgent;
        }
      }

      // Use the specified authorization header name if it's different
      if (authorizationHeaderName !== 'Authorization') {
        headers[authorizationHeaderName] = headers['Authorization'];
        delete headers['Authorization']; // Remove the default one
      }

      const proxyRequestOptions = {
        method: req.method,
        headers: headers,
        hostname: parsedTargetUrl.hostname,
        port: parsedTargetUrl.port || (parsedTargetUrl.protocol === 'https:' ? 443 : 80),
        path: parsedTargetUrl.pathname + req.url, // Append original request path to target URL's path
      };

      // Log request details. This will be captured by Jest's spy in tests.
      console.error(`CloudRunOIDCProxy: Proxying ${req.method} ${req.url} to ${targetUrl}${req.url}`);
      console.error('CloudRunOIDCProxy: Request headers:', proxyRequestOptions.headers);
      console.error('CloudRunOIDCProxy: Request body size (bytes):', incomingBody.length);


      const proxyReq = proxyProtocol.request(proxyRequestOptions, (proxyRes) => {
        // Copy all headers from Cloud Run response back to client
        for (const key in proxyRes.headers) {
          // Handle Location header for redirects, modifying to local proxy address
          if (key.toLowerCase() === 'location') {
            try {
              const locationURL = new URL(proxyRes.headers[key]);
              if (locationURL.hostname === parsedTargetUrl.hostname) {
                locationURL.protocol = 'http:'; // Always http for local proxy
                locationURL.host = bindAddress;
                res.setHeader(key, locationURL.toString());
                continue; // Skip the default header copy for Location
              }
            } catch (err) {
              // Log error parsing Location header. This will be captured by Jest's spy in tests.
              console.error(`CloudRunOIDCProxy: Error parsing Location header: ${err.message}`);
              // Fall through to copy original if parsing fails
            }
          }
          res.setHeader(key, proxyRes.headers[key]);
        }

        res.writeHead(proxyRes.statusCode);
        proxyRes.pipe(res); // Stream response directly back to client
      });

      proxyReq.on('error', (e) => {
        // Log proxy request error. This will be captured by Jest's spy in tests.
        console.error(`CloudRunOIDCProxy: Proxy request error to Cloud Run: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: {
              code: -32000,
              message: `Proxy failed to connect to Cloud Run service: ${e.message}`,
            },
          }));
        } else {
          res.end(); // If headers sent, just end the response to prevent further errors
        }
      });

      proxyReq.write(incomingBody);
      proxyReq.end();
    });

    req.on('error', (err) => {
      // Log incoming request error. This will be captured by Jest's spy in tests.
      console.error(`CloudRunOIDCProxy: Incoming request error: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: {
            code: -32000,
            message: `Proxy encountered error with incoming request: ${err.message}`,
          },
        }));
      } else {
        res.end();
      }
    });
  });

  server.listen(parseInt(bindAddress.split(':')[1]), bindAddress.split(':')[0], () => {
    // Log server listening. This will be captured by Jest's spy in tests.
    console.error(`CloudRunOIDCProxy: Proxy server listening on http://${bindAddress}`);
    console.error(`CloudRunOIDCProxy: Proxying requests to ${targetUrl}`);
  });

  // Return the server instance so it can be closed in tests
  return server;
}

// Main execution block - only runs if executed directly (not imported as a module)
// This pattern checks if the current module is the entry point in ES module scope.
if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  (async () => {
    const args = process.argv.slice(2);
    let targetCloudRunUrl = '';
    let bindAddress = DEFAULT_BIND_ADDRESS;
    let prependUserAgent = true;
    let authorizationHeaderName = DEFAULT_AUTHORIZATION_HEADER;

    // Check for basic usage error first (e.g., no arguments or only flags without --host)
    if (args.length === 0 || (args.length === 1 && args[0].startsWith('--'))) {
      console.error("Usage: node cloud-run-oidc-proxy.js --host <CLOUD_RUN_SERVICE_URL> [--bind <host:port>] [--prepend-user-agent] [--authorization-header <header-name>]");
      console.error("Example: node cloud-run-oidc-proxy.js --host https://my-service-xxxx.run.app --bind 127.0.0.1:8080");
      process.exit(1);
    }

    // Argument parsing
    // This simple loop processes arguments assuming --flag value pairs or a direct URL
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--host' && args[i + 1]) {
        targetCloudRunUrl = args[++i];
      } else if (args[i] === '--bind' && args[i + 1]) {
        bindAddress = args[++i];
      } else if (args[i] === '--prepend-user-agent') {
        prependUserAgent = true;
      } else if (args[i] === '--no-prepend-user-agent') {
        prependUserAgent = false;
      } else if (args[i] === '--authorization-header' && args[i + 1]) {
        authorizationHeaderName = args[++i];
      } else if (!targetCloudRunUrl && !args[i].startsWith('--')) {
        // If targetUrl not yet set, and it's not a flag, treat as targetUrl
        targetCloudRunUrl = args[i];
      }
    }

    if (!targetCloudRunUrl) {
      console.error("Error: Missing Cloud Run Service URL. Use --host <URL>.");
      process.exit(1);
    }

    // Perform an initial token fetch and ensure we can connect
    try {
      await getOrRefreshIdToken(targetCloudRunUrl);
    } catch (error) {
      process.exit(1);
    }

    const server = startProxyServer(targetCloudRunUrl, bindAddress, prependUserAgent, authorizationHeaderName);

    // Handle graceful shutdown for the main process
    process.on('SIGINT', () => {
      console.error('\nCloudRunOIDCProxy: SIGINT received. Shutting down gracefully...');
      server.close(() => {
        console.error('CloudRunOIDCProxy: Server closed.');
        if (tokenRefreshTimeout) {
          clearTimeout(tokenRefreshTimeout);
        }
        process.exit(0);
      });
    });

    process.on('SIGTERM', () => {
      console.error('\nCloudRunOIDCProxy: SIGTERM received. Shutting down gracefully...');
      server.close(() => {
        console.error('CloudRunOIDCProxy: Server closed.');
        if (tokenRefreshTimeout) {
          clearTimeout(tokenRefreshTimeout);
        }
        process.exit(0);
      });
    });
  })();
}