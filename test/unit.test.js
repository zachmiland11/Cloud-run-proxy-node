// Mock the google-auth-library before any imports that might use it
// This ensures the mock is active from the very beginning of the module's loading process.
// We use a factory function here to ensure a fresh set of mocks when resetModules is called.
jest.mock('google-auth-library', () => {
  const mockIdTokenClientInstance = {
    idTokenProvider: {
      fetchIdToken: jest.fn(),
    },
  };
  const MockGoogleAuthConstructor = jest.fn(() => ({
    getIdTokenClient: jest.fn(() => Promise.resolve(mockIdTokenClientInstance)),
  }));

  return {
    GoogleAuth: MockGoogleAuthConstructor,
    mockFetchIdToken: mockIdTokenClientInstance.idTokenProvider.fetchIdToken, // Export the specific mock for direct use
    // Also export the constructor mock if you need to clear its call history separately
    MockGoogleAuthConstructor: MockGoogleAuthConstructor,
  };
});

// These imports must come AFTER the jest.mock calls
// We'll use local variables to store the dynamically re-imported module functions in beforeEach
// to ensure each test operates on a fresh state.
let decodeJwt, getOrRefreshIdToken, _resetProxyState;
let mockFetchIdToken; // This will be assigned the actual mock from the library
let MockGoogleAuthConstructor; // This will be assigned the actual mock constructor

describe('decodeJwt', () => {
  // We'll dynamically import decodeJwt in beforeEach to ensure consistent state
  beforeEach(() => {
    // Clear module cache to ensure a fresh import for each test
    jest.resetModules();
    const reImportedModule = require('../cloud-run-oidc-proxy.js');
    decodeJwt = reImportedModule.decodeJwt;
    // Spy on console.error for these tests too, to prevent output
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    console.error.mockRestore(); // Restore console.error after each test
  });

  it('should correctly decode a valid JWT', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ exp: Date.now() / 1000 + 3600, sub: 'user123' })).toString('base64url');
    const signature = 'signature';
    const jwt = `${header}.${payload}.${signature}`;

    const decoded = decodeJwt(jwt);
    expect(decoded).toEqual({ exp: expect.any(Number), sub: 'user123' });
    expect(decoded.exp).toBeGreaterThan(Date.now() / 1000);
  });

  it('should throw an error for an invalid JWT format (too few parts)', () => {
    const jwt = 'header.payload';
    expect(() => decodeJwt(jwt)).toThrow('Invalid JWT format');
  });

  it('should throw an error for an invalid JWT format (too many parts)', () => {
    const jwt = 'header.payload.signature.extra';
    expect(() => decodeJwt(jwt)).toThrow('Invalid JWT format');
  });

  it('should throw an error for malformed base64 payload', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = 'invalid_base64!'; // Malformed base64 will produce non-parseable JSON
    const signature = 'signature';
    const jwt = `${header}.${payload}.${signature}`;

    // Expect a SyntaxError from JSON.parse
    expect(() => decodeJwt(jwt)).toThrow(SyntaxError);
  });

  it('should throw an error for non-JSON payload', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from('not json').toString('base64url');
    const signature = 'signature';
    const jwt = `${header}.${payload}.${signature}`;

    // Expect a SyntaxError from JSON.parse
    expect(() => decodeJwt(jwt)).toThrow(SyntaxError);
  });
});

describe('getOrRefreshIdToken', () => {
  const AUDIENCE = 'https://my-cloud-run-service.run.app';
  const MOCK_TOKEN_BASE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'; // Base64url encoded header

  beforeEach(() => {
    // Clear module cache to ensure a fresh import for each test,
    // preventing global state leakage between tests.
    jest.resetModules();

    // Re-import the module and its functions after clearing cache
    const reImportedModule = require('../cloud-run-oidc-proxy.js');
    decodeJwt = reImportedModule.decodeJwt;
    getOrRefreshIdToken = reImportedModule.getOrRefreshIdToken;
    _resetProxyState = reImportedModule._resetProxyState;

    // Get a fresh reference to the mocked fetchIdToken and GoogleAuthConstructor from the re-mocked library
    const googleAuthLibrary = require('google-auth-library');
    mockFetchIdToken = googleAuthLibrary.mockFetchIdToken;
    MockGoogleAuthConstructor = googleAuthLibrary.MockGoogleAuthConstructor;


    // Use fake timers after all module imports and mocks are set up
    jest.useFakeTimers();

    // Now call the reset and clear mocks using the freshly imported and mocked references
    _resetProxyState(); // Reset state of the re-imported module
    mockFetchIdToken.mockClear(); // Clear the specific fetchIdToken mock calls
    MockGoogleAuthConstructor.mockClear(); // Clear the GoogleAuth constructor calls

    jest.spyOn(console, 'error').mockImplementation(() => {}); // Spy on console.error
  });

  afterEach(() => {
    jest.runOnlyPendingTimers(); // Ensure all pending timers are run
    jest.clearAllTimers();
    jest.useRealTimers();
    console.error.mockRestore(); // Restore console.error
  });

  it('should fetch a new token if no token is cached', async () => {
    const expiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiry
    const mockTokenPayload = Buffer.from(JSON.stringify({ exp: expiry, aud: AUDIENCE })).toString('base64url');
    const mockToken = `${MOCK_TOKEN_BASE}.${mockTokenPayload}.signature`;
    mockFetchIdToken.mockResolvedValueOnce(mockToken);

    const token = await getOrRefreshIdToken(AUDIENCE);
    expect(token).toBe(mockToken);
    // Correct assertion: Get the getIdTokenClient from the *first* instance created by the mock constructor
    expect(MockGoogleAuthConstructor.mock.results[0].value.getIdTokenClient).toHaveBeenCalledWith(AUDIENCE);
    expect(mockFetchIdToken).toHaveBeenCalledWith(AUDIENCE);
  });

  it('should return cached token if it is still valid', async () => {
    const expiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiry
    const mockTokenPayload = Buffer.from(JSON.stringify({ exp: expiry, aud: AUDIENCE })).toString('base64url');
    const mockToken = `${MOCK_TOKEN_BASE}.${mockTokenPayload}.signature`;
    mockFetchIdToken.mockResolvedValue(mockToken); // Will be called once initially

    // First call, token is fetched and cached
    const token1 = await getOrRefreshIdToken(AUDIENCE);
    expect(token1).toBe(mockToken);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);

    // Second call immediately after, should return cached token
    const token2 = await getOrRefreshIdToken(AUDIENCE);
    expect(token2).toBe(mockToken);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1); // Still only one fetch
  });

  it('should refresh token if cached token is nearing expiration', async () => {
    // Set first token to expire just slightly beyond the refresh buffer,
    // so `refreshDelayMs` becomes a small positive number or 0.
    // Example: expiry 5 minutes (300s) + 1 second. Buffer is 300s.
    // So refreshDelayMs = (301 - 300) * 1000 = 1000ms.
    const expiry1 = Math.floor(Date.now() / 1000) + (300 + 1); // 5 min + 1 sec
    const mockTokenPayload1 = Buffer.from(JSON.stringify({ exp: expiry1, aud: AUDIENCE })).toString('base64url');
    const mockToken1 = `${MOCK_TOKEN_BASE}.${mockTokenPayload1}.signature1`;

    // Token for refresh, expires in 1 hour
    const expiry2 = Math.floor(Date.now() / 1000) + 3600;
    const mockTokenPayload2 = Buffer.from(JSON.stringify({ exp: expiry2, aud: AUDIENCE })).toString('base64url');
    const mockToken2 = `${MOCK_TOKEN_BASE}.${mockTokenPayload2}.signature2`;

    mockFetchIdToken.mockResolvedValueOnce(mockToken1); // First fetch
    mockFetchIdToken.mockResolvedValueOnce(mockToken2); // Second fetch (refresh)

    // First call, gets token1
    const token = await getOrRefreshIdToken(AUDIENCE);
    expect(token).toBe(mockToken1);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);

    // Advance timers past the refresh delay for mockToken1
    // It should now trigger the refresh automatically.
    jest.runAllTimers(); // Use runAllTimers to ensure async callbacks within setTimeout are processed

    expect(mockFetchIdToken).toHaveBeenCalledTimes(2); // Token should have been refreshed
    // The cachedToken should now be mockToken2, but we can't directly assert it here from outside
  });

  it('should handle token fetch errors gracefully and re-throw', async () => {
    const errorMessage = 'Authentication failed';
    mockFetchIdToken.mockRejectedValueOnce(new Error(errorMessage));

    await expect(getOrRefreshIdToken(AUDIENCE)).rejects.toThrow(errorMessage);
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);
    // Expect error messages to be logged to console.error
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('ERROR fetching OIDC token'));
    // The specific 'Please ensure your local...' message is also logged
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('Please ensure your local'));
  });

  it('should clear existing refresh timeout when a new token is fetched', async () => {
    // First token expires far in future, sets a timeout
    // Set expiry so it's far enough not to trigger auto-refresh for now
    const expiry1 = Math.floor(Date.now() / 1000) + 7200; // 2 hours
    const mockTokenPayload1 = Buffer.from(JSON.stringify({ exp: expiry1, aud: AUDIENCE })).toString('base64url');
    const mockToken1 = `${MOCK_TOKEN_BASE}.${mockTokenPayload1}.signature1`;

    // Second token also expires far in future. The crucial part for this test
    // is that it triggers a new `getOrRefreshIdToken` call which causes a new fetch,
    // thereby demonstrating that the previous timeout is cleared.
    const expiry2 = Math.floor(Date.now() / 1000) + 10800; // 3 hours
    const mockTokenPayload2 = Buffer.from(JSON.stringify({ exp: expiry2, aud: AUDIENCE })).toString('base64url');
    const mockToken2 = `${MOCK_TOKEN_BASE}.${mockTokenPayload2}.signature2`;

    mockFetchIdToken.mockResolvedValueOnce(mockToken1);
    mockFetchIdToken.mockResolvedValueOnce(mockToken2);

    // Mock setTimeout and clearTimeout
    jest.spyOn(global, 'setTimeout');
    jest.spyOn(global, 'clearTimeout');

    await getOrRefreshIdToken(AUDIENCE); // Sets timeout for mockToken1
    expect(mockFetchIdToken).toHaveBeenCalledTimes(1);
    expect(setTimeout).toHaveBeenCalledTimes(1);
    const initialTimeoutId = setTimeout.mock.results[0].value; // Get the ID of the first timeout

    jest.advanceTimersByTime(1000); // Advance a little, but not enough for refresh

    // Force a new token fetch by resetting the cached token state.
    // This simulates a scenario where a new token is explicitly requested
    // (e.g., due to an external trigger, or simply calling the function again when not cached).
    _resetProxyState(); // Crucial: This clears the internal module state, forcing a re-fetch

    await getOrRefreshIdToken(AUDIENCE); // Second call, will fetch mockToken2
    expect(mockFetchIdToken).toHaveBeenCalledTimes(2);
    // A new timeout should be set, and the old one cleared.
    expect(clearTimeout).toHaveBeenCalledTimes(1); // clear old timeout
    expect(clearTimeout).toHaveBeenCalledWith(initialTimeoutId); // And specifically that one
    expect(setTimeout).toHaveBeenCalledTimes(2); // set new timeout

    // Restore timers and clearTimeout/setTimeout spies
    global.setTimeout.mockRestore();
    global.clearTimeout.mockRestore();
  });
});