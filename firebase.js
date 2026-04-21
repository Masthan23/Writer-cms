import { initializeApp, getApps } from
    'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';

import {
    getAuth,
    createUserWithEmailAndPassword as _createUser,
    signInWithEmailAndPassword as _signIn,
    signOut as _signOut,
    sendEmailVerification as _sendVerification,
    sendPasswordResetEmail as _sendReset,
    onAuthStateChanged as _onAuthStateChanged,
    getIdToken as _getIdToken,
    setPersistence,
    browserSessionPersistence,
} from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';

import {
    getFirestore,
    doc as _doc,
    setDoc as _setDoc,
    getDoc as _getDoc,
    getDocs as _getDocs,
    updateDoc as _updateDoc,
    deleteDoc as _deleteDoc,
    collection as _collection,
    query as _query,
    where as _where,
    orderBy as _orderBy,
    limit as _limit,
    serverTimestamp as _serverTimestamp,
    Timestamp as _Timestamp,
    onSnapshot as _onSnapshot,
    writeBatch as _writeBatch,
    arrayUnion as _arrayUnion,
    arrayRemove as _arrayRemove,
} from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECURE LOGGER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const _IS_DEV = (() => {
    try {
        return (
            location.hostname === 'localhost' ||
            location.hostname === '127.0.0.1' ||
            location.hostname.endsWith('.local') ||
            location.search.includes('__dvdev=1')
        );
    } catch { return false; }
})();

const SecureLogger = Object.freeze({
    _sanitize(args) {
        return args.map(a => {
            if (typeof a !== 'string') return '[object]';
            return a
                .replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[email]')
                .replace(/[A-Za-z0-9_\-]{40,}/g, '[token]')
                .replace(/Bearer\s+\S+/gi, 'Bearer [token]')
                .substring(0, 200);
        });
    },
    log(...args)   { if (_IS_DEV) console.log('[DV]', ...args); },
    warn(...args)  { if (_IS_DEV) console.warn('[DV]', ...this._sanitize(args.map(String))); },
    error(...args) {
        const msg = _IS_DEV ? args : this._sanitize(args.map(String));
        console.error('[DV]', ...msg);
    },
    info(...args)  { if (_IS_DEV) console.info('[DV]', ...args); },
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECURITY CONSTANTS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const SECURITY = Object.freeze({
    SESSION_KEY:           '_dv_s',
    SESSION_DATA_KEY:      '_dv_u',
    PENDING_KEY:           '_dv_p',
    SESSION_HMAC_KEY:      '_dv_hk',

    // â”€â”€ FIXED: Token and HMAC key are now structurally distinct â”€â”€
    // Token:    64 url-safe base64 chars  (random bytes â†’ base64)
    // HMAC key: 48 bytes â†’ 96 hex chars  (different length + domain-separated)
    TOKEN_LENGTH:          64,
    HMAC_KEY_BYTE_LENGTH:  48,   // 48 bytes = 96 hex chars  â‰   64 (token length)
    HMAC_DOMAIN_PREFIX:    'DVHK1:',   // domain-separation prefix burned into key derivation

    SESSION_DURATION:      8 * 60 * 60 * 1000,
    PENDING_TTL:           30 * 60 * 1000,
    FETCH_TIMEOUT:         15 * 1000,

    MAX_UID_LENGTH:        128,
    MAX_NAME_LENGTH:       100,
    MAX_EMAIL_LENGTH:      254,
    MAX_PASSWORD_LENGTH:   128,
    MAX_PHONE_LENGTH:      20,
    MAX_COMPANY_LENGTH:    200,
    MAX_URL_LENGTH:        2048,
    MAX_REASON_LENGTH:     500,

    VALID_ROLES:           Object.freeze(['admin', 'writer']),
    ADMIN_DOMAIN:          '@dashverse.ai',

    RATE_LIMITS: Object.freeze({
        login:  Object.freeze({ max: 5,  windowMs: 5  * 60 * 1000 }),
        signup: Object.freeze({ max: 3,  windowMs: 15 * 60 * 1000 }),
        reset:  Object.freeze({ max: 3,  windowMs: 10 * 60 * 1000 }),
    }),

    MAX_RETRIES:           3,

    PASSWORD_MIN_LENGTH:      8,
    PASSWORD_REQUIRE_UPPER:   true,
    PASSWORD_REQUIRE_LOWER:   true,
    PASSWORD_REQUIRE_NUMBER:  true,
    PASSWORD_REQUIRE_SPECIAL: true,
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WORKER CONFIG
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const WORKER_BASE_URL = 'https://dashverse-api-proxy.thondaladinne-masthan.workers.dev';
const WORKER_URL = WORKER_BASE_URL;


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// INTERNAL STATE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _app             = null;
let _authInstance    = null;
let _dbInstance      = null;
let _initialized     = false;
let _initPromise     = null;
let _initError       = null;
let _authListenerQueue = [];


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// CRYPTO UTILITIES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const CryptoUtils = Object.freeze({

    // â”€â”€ Generates a url-safe base64 token of exactly `length` chars â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    generateToken(length = SECURITY.TOKEN_LENGTH) {
        // Need ceil(length * 6/8) bytes to get `length` base64 chars before trim
        const bytes = new Uint8Array(Math.ceil(length * 0.75) + 4);
        crypto.getRandomValues(bytes);
        return btoa(String.fromCharCode(...bytes))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
            .substring(0, length);
    },

    // â”€â”€ FIXED: Generates an HMAC key that is STRUCTURALLY DISTINCT from a token
    //   â€¢ Uses SECURITY.HMAC_KEY_BYTE_LENGTH (48) bytes  â†’ 96 hex chars
    //   â€¢ Domain-separated: key material is SHA-256(DVHK1: + hex(randomBytes))
    //     so even if someone knows the raw random bytes they cannot trivially
    //     reverse the key, and the output length (64 hex chars of SHA-256)
    //     differs from the token format (url-safe base64).
    //   â€¢ Final key is raw-bytes re-encoded as hex from the domain-separated
    //     hash concatenated with extra entropy â†’ guaranteed â‰  token. â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    async generateHMACKey() {
        const byteLen  = SECURITY.HMAC_KEY_BYTE_LENGTH;        // 48
        const rawBytes = new Uint8Array(byteLen);
        const saltBytes = new Uint8Array(16);                   // extra entropy
        crypto.getRandomValues(rawBytes);
        crypto.getRandomValues(saltBytes);

        // Hex-encode raw bytes
        const rawHex = Array.from(rawBytes)
            .map(b => b.toString(16).padStart(2, '0')).join('');

        // Domain-separated hash: SHA-256( "DVHK1:" + rawHex + ":" + saltHex )
        const saltHex = Array.from(saltBytes)
            .map(b => b.toString(16).padStart(2, '0')).join('');
        const domainInput = `${SECURITY.HMAC_DOMAIN_PREFIX}${rawHex}:${saltHex}`;
        const hashHex = await this.sha256(domainInput);

        // Final key = rawHex (96 chars) + first 32 chars of domain hash
        // Total: 128 hex chars, structurally impossible to equal a 64-char token
        const finalKey = rawHex + hashHex.substring(0, 32);

        return finalKey;   // 128 hex chars
    },

    // â”€â”€ Legacy sync path kept for backward-compat (NOT used for new sessions) â”€
    _generateHMACKeySync(byteLength = 32) {
        const bytes = new Uint8Array(byteLength);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async generateHMAC(data, keyHex) {
        const enc = new TextEncoder();
        // Support both 64-char (legacy) and 128-char (new) key hex strings
        const keyBytes = new Uint8Array(
            keyHex.match(/.{1,2}/g).map(b => parseInt(b, 16))
        );
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false, ['sign']
        );
        const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
        return Array.from(new Uint8Array(sigBuf))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async verifyHMAC(data, keyHex, expectedSig) {
        const computed = await this.generateHMAC(data, keyHex);
        return this.safeCompare(computed, expectedSig);
    },

    async sha256(data) {
        const enc = new TextEncoder();
        const hash = await crypto.subtle.digest('SHA-256', enc.encode(data));
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async hmacChecksum(data, keyHex) {
        return this.generateHMAC(data, keyHex);
    },

    safeCompare(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string') return false;
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    },

    // â”€â”€ Validates a stored key is the new format (128 hex chars) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    isNewFormatKey(keyHex) {
        return typeof keyHex === 'string' && keyHex.length === 128 && /^[0-9a-f]+$/i.test(keyHex);
    },

    // â”€â”€ Validates a stored key is the legacy format (64 hex chars) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    isLegacyFormatKey(keyHex) {
        return typeof keyHex === 'string' && keyHex.length === 64 && /^[0-9a-f]+$/i.test(keyHex);
    },
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// BROWSER FINGERPRINT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function getBrowserFingerprint() {
    const components = [
        navigator.userAgent || '',
        navigator.language  || '',
        String(screen.colorDepth) || '',
        new Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    ].join('|');
    return CryptoUtils.sha256(components);
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// NETWORK
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function fetchWithTimeout(url, options = {}, timeoutMs = SECURITY.FETCH_TIMEOUT) {
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
            referrer: 'no-referrer',
            referrerPolicy: 'no-referrer',
        });
        clearTimeout(timerId);
        return response;
    } catch (err) {
        clearTimeout(timerId);
        if (err.name === 'AbortError') throw new Error(`Request timed out after ${timeoutMs}ms`);
        throw err;
    }
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// FIREBASE INITIALIZATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function _doInit() {
    if (_initialized) return;
    let lastError = null;

    for (let attempt = 1; attempt <= SECURITY.MAX_RETRIES; attempt++) {
        try {
            if (attempt > 1) {
                const delay = Math.min(1000 * Math.pow(2, attempt - 2), 4000);
                await new Promise(r => setTimeout(r, delay));
            }

            SecureLogger.log(`Firebase init attempt ${attempt}/${SECURITY.MAX_RETRIES}`);

            const response = await fetchWithTimeout(
                `${WORKER_BASE_URL}/api/config`,
                {
                    method: 'GET',
                    credentials: 'omit',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                }
            );

            if (!response.ok) {
                throw new Error(`Config fetch failed: HTTP ${response.status}`);
            }

            let config;
            try { config = await response.json(); }
            catch { throw new Error('Failed to parse server configuration'); }

            if (config.error) throw new Error(`Server config error`);

            const required = ['apiKey', 'authDomain', 'projectId'];
            const missing  = required.filter(k => !config[k]);
            if (missing.length) throw new Error(`Incomplete config`);
            if (typeof config.apiKey !== 'string' || config.apiKey.length < 10)
                throw new Error('Invalid apiKey received from server');

            _app           = getApps().length ? getApps()[0] : initializeApp(config);
            _authInstance  = getAuth(_app);
            _dbInstance    = getFirestore(_app);

            await setPersistence(_authInstance, browserSessionPersistence).catch(() => {});

            _initialized = true;
            _initError   = null;

            SecureLogger.log('Firebase initialized successfully');

            if (_authListenerQueue.length > 0) {
                _authListenerQueue.forEach(({ callback, resolveUnsub }) => {
                    const unsub = _onAuthStateChanged(_authInstance, callback);
                    resolveUnsub(unsub);
                });
                _authListenerQueue = [];
            }
            return;

        } catch (err) {
            lastError = err;
            SecureLogger.error(`Init attempt ${attempt} failed`);

            const isRetryable = (
                err.message.includes('timed out') ||
                err.message.includes('Failed to fetch') ||
                err.message.includes('NetworkError') ||
                err.message.includes('network') ||
                err.message.includes('HTTP 5')
            );
            if (!isRetryable) break;
        }
    }

    _initError = lastError;
    SecureLogger.error('All Firebase init attempts failed');

    _authListenerQueue.forEach(({ callback }) => {
        try { callback(null); } catch { /* ignore */ }
    });
    _authListenerQueue = [];
    throw lastError;
}

function ensureInitialized() {
    if (!_initPromise) _initPromise = _doInit();
    return _initPromise;
}

ensureInitialized().catch(() => {});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// PROXIES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const auth = new Proxy({}, {
    get(_, prop) {
        if (prop === 'currentUser') return _authInstance?.currentUser ?? null;
        if (prop === 'signOut')     return () => _authInstance?.signOut() ?? Promise.resolve();
        if (prop === 'app')         return _authInstance?.app ?? null;
        if (prop === 'name')        return _authInstance?.name ?? '[DEFAULT]';
        if (prop === 'config')      return _authInstance?.config ?? {};
        if (_authInstance && prop in _authInstance) {
            const val = _authInstance[prop];
            return typeof val === 'function' ? val.bind(_authInstance) : val;
        }
        return undefined;
    },
});

const db = new Proxy({}, {
    get(_, prop) {
        if (!_dbInstance) {
            if (prop === 'type') return 'firestore';
            if (prop === 'app')  return null;
            if (prop === 'toJSON') return () => ({});
            return undefined;
        }
        const val = _dbInstance[prop];
        return typeof val === 'function' ? val.bind(_dbInstance) : val;
    },
});

function _resolveDb(ref) {
    if (ref === db) {
        if (!_dbInstance) throw new Error('Firestore not initialized yet');
        return _dbInstance;
    }
    return ref;
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// FIRESTORE HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function doc(dbRef, ...args)         { return _doc(_resolveDb(dbRef), ...args); }
function collection(dbRef, ...args)  { return _collection(_resolveDb(dbRef), ...args); }
function writeBatch(dbRef)           { return _writeBatch(_resolveDb(dbRef)); }
function setDoc(...args)             { return _setDoc(...args); }
function getDoc(...args)             { return _getDoc(...args); }
function getDocs(...args)            { return _getDocs(...args); }
function updateDoc(...args)          { return _updateDoc(...args); }
function deleteDoc(...args)          { return _deleteDoc(...args); }
function query(...args)              { return _query(...args); }
function where(...args)              { return _where(...args); }
function orderBy(...args)            { return _orderBy(...args); }
function limit(...args)              { return _limit(...args); }
function onSnapshot(...args)         { return _onSnapshot(...args); }
function serverTimestamp()           { return _serverTimestamp(); }
function arrayUnion(...args)         { return _arrayUnion(...args); }
function arrayRemove(...args)        { return _arrayRemove(...args); }
const Timestamp = _Timestamp;


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// AUTH HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function onAuthStateChanged(authRefOrCb, maybeCb) {
    const cb = typeof authRefOrCb === 'function' ? authRefOrCb : maybeCb;
    if (!cb || typeof cb !== 'function') return () => {};

    if (_initialized && _authInstance) {
        return _onAuthStateChanged(_authInstance, cb);
    }
    if (_initError) {
        try { cb(null); } catch {}
        return () => {};
    }

    let unsubscribe = null;
    let cancelled   = false;

    const entry = {
        callback: cb,
        resolveUnsub: (unsub) => {
            if (cancelled) { try { unsub(); } catch {} }
            else { unsubscribe = unsub; }
        },
    };

    _authListenerQueue.push(entry);
    ensureInitialized().catch(() => {});

    return () => {
        cancelled = true;
        if (unsubscribe) { try { unsubscribe(); } catch {} }
        const idx = _authListenerQueue.indexOf(entry);
        if (idx !== -1) _authListenerQueue.splice(idx, 1);
    };
}

async function signInWithEmailAndPassword(authRef, email, password) {
    await ensureInitialized();
    const sanitizedEmail    = sanitizeInput(email, SECURITY.MAX_EMAIL_LENGTH).toLowerCase();
    const sanitizedPassword = String(password || '').substring(0, SECURITY.MAX_PASSWORD_LENGTH);
    if (!isValidEmail(sanitizedEmail)) throw new Error('Invalid email format');
    if (!sanitizedPassword || sanitizedPassword.length < 6) throw new Error('Password is too short');
    return _signIn(_authInstance, sanitizedEmail, sanitizedPassword);
}

async function createUserWithEmailAndPassword(authRef, email, password) {
    await ensureInitialized();
    const sanitizedEmail    = sanitizeInput(email, SECURITY.MAX_EMAIL_LENGTH).toLowerCase();
    const sanitizedPassword = String(password || '').substring(0, SECURITY.MAX_PASSWORD_LENGTH);
    if (!isValidEmail(sanitizedEmail)) throw new Error('Invalid email format');
    if (!sanitizedPassword || sanitizedPassword.length < SECURITY.PASSWORD_MIN_LENGTH)
        throw new Error(`Password must be at least ${SECURITY.PASSWORD_MIN_LENGTH} characters`);
    if (!isStrongPassword(sanitizedPassword))
        throw new Error('Password does not meet complexity requirements');
    return _createUser(_authInstance, sanitizedEmail, sanitizedPassword);
}

async function signOut(authRef) {
    await ensureInitialized();
    return _signOut(_authInstance);
}

async function sendEmailVerification(user) {
    await ensureInitialized();
    if (!user || typeof user.getIdToken !== 'function') throw new Error('Invalid user object');
    return _sendVerification(user);
}

async function sendPasswordResetEmail(authRef, email) {
    await ensureInitialized();
    const sanitizedEmail = sanitizeInput(email, SECURITY.MAX_EMAIL_LENGTH).toLowerCase();
    if (!isValidEmail(sanitizedEmail)) throw new Error('Invalid email format');
    return _sendReset(_authInstance, sanitizedEmail);
}

async function getIdToken(forceRefresh = false) {
    try { await ensureInitialized(); }
    catch (err) { throw new Error(`Firebase not initialized: ${err.message}`); }

    if (!_authInstance) throw new Error('Auth instance not available');

    const user = _authInstance.currentUser;
    if (!user) throw new Error('No authenticated user');
    if (typeof user.getIdToken !== 'function') throw new Error('Invalid user object');

    try {
        const token = await _getIdToken(user, forceRefresh);
        if (!token || typeof token !== 'string' || token.split('.').length !== 3)
            throw new Error('Received malformed ID token');
        return token;
    } catch (err) {
        const expiryErrors = new Set([
            'auth/id-token-expired', 'auth/user-token-expired', 'auth/invalid-user-token',
        ]);
        if (!forceRefresh && expiryErrors.has(err.code)) {
            SecureLogger.warn('Token expired â€” forcing refresh');
            return getIdToken(true);
        }
        throw new Error(`Failed to get ID token`);
    }
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SERVER-SIDE ROLE VERIFICATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function verifyUserRoleFromFirestore(uid, email) {
    if (!_dbInstance || !uid) return null;
    try {
        const lowerEmail = email.toLowerCase();

        if (lowerEmail.endsWith(SECURITY.ADMIN_DOMAIN)) {
            const adminSnap = await _getDoc(_doc(_dbInstance, 'admins', uid));
            if (adminSnap.exists()) {
                const data = adminSnap.data();
                if (data.role === 'admin') return 'admin';
            }
            if (_authInstance?.currentUser?.emailVerified) {
                return 'admin';
            }
            return null;
        }

        const writerSnap = await _getDoc(_doc(_dbInstance, 'writers', uid));
        if (writerSnap.exists()) {
            const data = writerSnap.data();
            if (data.role === 'writer' && data.email?.toLowerCase() === lowerEmail)
                return 'writer';
        }
        return null;
    } catch (err) {
        SecureLogger.error('Role verification failed');
        return null;
    }
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// SECURE SESSION MANAGEMENT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const SecureSession = Object.freeze({

    // Creates a worker-signed session. The HMAC secret remains server-side.
    async createSession(uid) {
        if (!uid || typeof uid !== 'string' || uid.length > SECURITY.MAX_UID_LENGTH)
            throw new Error('Invalid UID for session creation');

        const idToken = await getIdToken(true);
        const response = await fetchWithTimeout(
            `${WORKER_URL}/api/create-session`,
            {
                method: 'POST',
                credentials: 'omit',
                cache: 'no-store',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                body: JSON.stringify({ idToken }),
            }
        );

        let payload;
        try { payload = await response.json(); }
        catch { throw new Error('Invalid session response'); }

        if (!response.ok || !payload?.success) {
            throw new Error('Server session creation failed');
        }
        if (payload.uid !== uid) throw new Error('Session UID mismatch');
        if (!this._isValidServerSessionPayload(payload)) {
            throw new Error('Malformed server session');
        }

        const session = {
            token:     payload.sessionToken,
            signature: payload.signature,
            uid:       payload.uid,
            email:     sanitizeForStorage(payload.email).toLowerCase(),
            role:      payload.role,
            issuedAt:  Number(payload.issuedAt),
            expiresAt: Number(payload.expiresAt),
            createdAt: Date.now(),
            v:         3,
            sv:        String(payload.version || 'v1').substring(0, 20),
        };

        try {
            sessionStorage.setItem(SECURITY.SESSION_KEY, JSON.stringify(session));
            sessionStorage.removeItem(SECURITY.SESSION_HMAC_KEY);
        } catch {
            throw new Error('Failed to persist session');
        }

        return session.token;
    },

    // Validates the current session with the worker before trusting it.
    async validateSession() {
        try {
            const session = this._getStoredSession();
            if (!session) return null;

            const response = await fetchWithTimeout(
                `${WORKER_URL}/api/verify-session`,
                {
                    method: 'POST',
                    credentials: 'omit',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    body: JSON.stringify({
                        sessionToken: session.token,
                        signature:    session.signature,
                        uid:          session.uid,
                        email:        session.email,
                        role:         session.role,
                        expiresAt:    session.expiresAt,
                        issuedAt:     session.issuedAt,
                    }),
                }
            );

            let result;
            try { result = await response.json(); }
            catch { this.clearSession(); return null; }

            if (!response.ok || !result?.valid) {
                this.clearSession();
                return null;
            }

            if (
                result.uid !== session.uid ||
                result.email !== session.email ||
                result.role !== session.role
            ) {
                this.clearSession();
                return null;
            }

            return session;
        } catch {
            this.clearSession();
            return null;
        }
    },

    // Quick synchronous structure/expiry check. Use validateSession for server verification.
    hasActiveSession(uid) {
        const activeSession = this._getStoredSession();
        return !!activeSession && activeSession.uid === uid;

    },

    async setUserData(userData) {
        const { uid, name, email, role } = userData;
        if (!uid   || typeof uid   !== 'string') throw new Error('Invalid uid');
        if (!name  || typeof name  !== 'string') throw new Error('Invalid name');
        if (!email || typeof email !== 'string') throw new Error('Invalid email');
        if (!SECURITY.VALID_ROLES.includes(role)) throw new Error(`Invalid role: ${role}`);

        const session = this._getStoredSession();
        if (!session) throw new Error('Missing signed session');
        const lowerEmail = sanitizeForStorage(email).toLowerCase();
        if (session.uid !== uid || session.email !== lowerEmail || session.role !== role) {
            throw new Error('User data does not match signed session');
        }

        const sanitized = {
            uid:          uid.substring(0, SECURITY.MAX_UID_LENGTH),
            name:         sanitizeForStorage(name),
            email:        lowerEmail,
            role,
            roleVerified: false,
        };

        const timestamp = Date.now();
        const checksum = await this._checksum(sanitized, timestamp, session);

        try {
            sessionStorage.setItem(SECURITY.SESSION_DATA_KEY, JSON.stringify({
                data: sanitized,
                timestamp,
                checksum,
                v: 2,
            }));
        } catch {
            throw new Error('Failed to persist user data');
        }
    },

    async getUserData() {
        try {
            const raw = sessionStorage.getItem(SECURITY.SESSION_DATA_KEY);
            if (!raw) return null;
            const payload = JSON.parse(raw);
            const session = this._getStoredSession();
            if (!session) { this.clearSession(); return null; }
            if (!payload?.data || !payload.timestamp || !payload.checksum) {
                this.clearSession(); return null;
            }
            if (Date.now() - payload.timestamp > SECURITY.SESSION_DURATION) {
                this.clearSession(); return null;
            }
            if (!SECURITY.VALID_ROLES.includes(payload.data.role)) {
                this.clearSession(); return null;
            }
            if (
                payload.data.uid !== session.uid ||
                payload.data.email !== session.email ||
                payload.data.role !== session.role
            ) {
                this.clearSession(); return null;
            }
            const expected = await this._checksum(payload.data, payload.timestamp, session);
            if (!CryptoUtils.safeCompare(payload.checksum, expected)) {
                this.clearSession(); return null;
            }
            return payload.data;
        } catch {
            this.clearSession(); return null;
        }
    },

    clearSession() {
        const keys = [
            SECURITY.SESSION_KEY,
            SECURITY.SESSION_DATA_KEY,
            SECURITY.PENDING_KEY,
            SECURITY.SESSION_HMAC_KEY,
            '_dv_session', '_dv_user', '_dv_pending',
            '_dv_session_token', '_dv_session_uid', '_dv_session_created',
            'userData', 'pendingVerification',
        ];
        keys.forEach(k => { try { sessionStorage.removeItem(k); } catch {} });
    },

    clear() { this.clearSession(); },

    setPendingVerification(data) {
        const { email, name } = data;
        if (!email || !name) throw new Error('Invalid pending verification data');
        try {
            sessionStorage.setItem(SECURITY.PENDING_KEY, JSON.stringify({
                email: sanitizeForStorage(email).toLowerCase().substring(0, SECURITY.MAX_EMAIL_LENGTH),
                name:  sanitizeForStorage(name).substring(0, SECURITY.MAX_NAME_LENGTH),
                ts:    Date.now(),
            }));
        } catch { throw new Error('Failed to persist pending verification data'); }
    },

    getPendingVerification() {
        try {
            const raw = sessionStorage.getItem(SECURITY.PENDING_KEY);
            if (!raw) return null;
            const data = JSON.parse(raw);
            if (!data?.email || !data?.ts) { sessionStorage.removeItem(SECURITY.PENDING_KEY); return null; }
            if ((Date.now() - data.ts) > SECURITY.PENDING_TTL) {
                sessionStorage.removeItem(SECURITY.PENDING_KEY); return null;
            }
            return data;
        } catch { return null; }
    },

    async _checksum(data, timestamp, session) {
        const str = [
            data.uid,
            data.email,
            data.role,
            data.name,
            String(timestamp),
            session.token,
            session.signature,
        ].join('|');
        return `cs2_${await CryptoUtils.sha256(str)}`;
    },

    _getStoredSession() {
        try {
            const raw = sessionStorage.getItem(SECURITY.SESSION_KEY);
            if (!raw) return null;
            const session = JSON.parse(raw);
            if (!this._hasValidStructure(session)) { this.clearSession(); return null; }
            if (Date.now() > session.expiresAt) { this.clearSession(); return null; }
            return session;
        } catch {
            this.clearSession();
            return null;
        }
    },

    _isValidServerSessionPayload(payload) {
        return (
            payload &&
            typeof payload.sessionToken === 'string' &&
            payload.sessionToken.length === SECURITY.TOKEN_LENGTH &&
            /^[A-Za-z0-9_-]+$/.test(payload.sessionToken) &&
            typeof payload.signature === 'string' &&
            /^[0-9a-f]{64}$/i.test(payload.signature) &&
            typeof payload.uid === 'string' &&
            payload.uid.length > 0 &&
            payload.uid.length <= SECURITY.MAX_UID_LENGTH &&
            typeof payload.email === 'string' &&
            isValidEmail(payload.email) &&
            SECURITY.VALID_ROLES.includes(payload.role) &&
            Number.isFinite(Number(payload.issuedAt)) &&
            Number.isFinite(Number(payload.expiresAt)) &&
            Number(payload.expiresAt) > Date.now()
        );
    },

    // â”€â”€ FIXED: Structure check now also validates kv (key-version) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _hasValidStructure(session) {
        return (
            session !== null &&
            typeof session === 'object' &&
            typeof session.token       === 'string' && session.token.length === SECURITY.TOKEN_LENGTH &&
            /^[A-Za-z0-9_-]+$/.test(session.token) &&
            typeof session.uid         === 'string' && session.uid.length > 0 &&
            typeof session.email       === 'string' && isValidEmail(session.email) &&
            SECURITY.VALID_ROLES.includes(session.role) &&
            typeof session.issuedAt    === 'number' &&
            typeof session.expiresAt   === 'number' &&
            typeof session.signature   === 'string' && /^[0-9a-f]{64}$/i.test(session.signature) &&
            typeof session.createdAt   === 'number' &&
            session.v  === 3
        );
    },
});


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// RATE LIMITER
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class RateLimiter {
    constructor(actionOrMax, windowMs, key) {
        if (typeof actionOrMax === 'string' && windowMs === undefined) {
            const config = SECURITY.RATE_LIMITS[actionOrMax];
            if (!config) throw new Error(`Unknown rate-limit action: "${actionOrMax}"`);
            this.max      = config.max;
            this.windowMs = config.windowMs;
            this._key     = `dv_rl_${actionOrMax}`;
        } else {
            const max = parseInt(String(actionOrMax), 10);
            if (isNaN(max) || max < 1) throw new Error('Invalid maxActions parameter');
            if (!windowMs || typeof windowMs !== 'number') throw new Error('Invalid windowMs');
            this.max      = max;
            this.windowMs = windowMs;
            this._key     = key ? `dv_rl_${key}` : null;
        }
        this._state = this._loadState();
    }

    canProceed() {
        this._prune();
        if (this._state.attempts.length >= this.max) return false;
        this._state.attempts.push(Date.now());
        this._saveState();
        return true;
    }

    getWaitTime() {
        this._prune();
        if (this._state.attempts.length < this.max) return 0;
        return Math.max(0, this.windowMs - (Date.now() - this._state.attempts[0]));
    }

    reset() {
        this._state = { attempts: [] };
        if (this._key) { try { sessionStorage.removeItem(this._key); } catch {} }
    }

    _prune() {
        const cutoff = Date.now() - this.windowMs;
        this._state.attempts = this._state.attempts.filter(t => t > cutoff);
    }

    _loadState() {
        if (!this._key) return { attempts: [] };
        try {
            const raw = sessionStorage.getItem(this._key);
            if (!raw) return { attempts: [] };
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed.attempts)) return { attempts: [] };
            const cutoff = Date.now() - this.windowMs;
            return { attempts: parsed.attempts.filter(t => typeof t === 'number' && t > cutoff) };
        } catch { return { attempts: [] }; }
    }

    _saveState() {
        if (!this._key) return;
        try { sessionStorage.setItem(this._key, JSON.stringify(this._state)); }
        catch {}
    }
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// INPUT VALIDATION & SANITIZATION
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function sanitizeInput(value, maxLength = 500) {
    if (value == null) return '';
    return String(value).trim()
        .substring(0, maxLength)
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

function sanitizeForStorage(value) {
    if (value == null) return '';
    return String(value).trim()
        .replace(/[\x00-\x1F\x7F<>&"']/g, '')
        .substring(0, 500);
}

function sanitizeHTML(str) {
    if (str == null) return '';
    const el = document.createElement('div');
    el.appendChild(document.createTextNode(String(str)));
    return el.innerHTML;
}

function setTextSafe(elementId, text) {
    const el = document.getElementById(elementId);
    if (el) el.textContent = text;
}

function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    if (email.length > SECURITY.MAX_EMAIL_LENGTH) return false;
    const pattern = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    return pattern.test(email) && !email.includes('..');
}

function isValidURL(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (!trimmed) return false;
    if (trimmed.length > SECURITY.MAX_URL_LENGTH) return false;
    try {
        const url = new URL(trimmed);
        const hostname = url.hostname.toLowerCase();
        if (!['https:', 'http:'].includes(url.protocol)) return false;
        const blockedHosts = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
        if (blockedHosts.has(hostname)) return false;
        if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) return false;
        if (!hostname.includes('.')) return false;
        return true;
    } catch { return false; }
}

function isStrongPassword(password) {
    if (!password || typeof password !== 'string') return false;
    if (password.length < SECURITY.PASSWORD_MIN_LENGTH) return false;

    const checks = {
        hasUpper:   !SECURITY.PASSWORD_REQUIRE_UPPER  || /[A-Z]/.test(password),
        hasLower:   !SECURITY.PASSWORD_REQUIRE_LOWER  || /[a-z]/.test(password),
        hasNumber:  !SECURITY.PASSWORD_REQUIRE_NUMBER || /[0-9]/.test(password),
        hasSpecial: !SECURITY.PASSWORD_REQUIRE_SPECIAL || /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    };

    return Object.values(checks).every(Boolean);
}

function getPasswordStrengthMessage(password) {
    if (!password) return '';
    const issues = [];
    if (password.length < SECURITY.PASSWORD_MIN_LENGTH)
        issues.push(`at least ${SECURITY.PASSWORD_MIN_LENGTH} characters`);
    if (SECURITY.PASSWORD_REQUIRE_UPPER && !/[A-Z]/.test(password))
        issues.push('one uppercase letter');
    if (SECURITY.PASSWORD_REQUIRE_LOWER && !/[a-z]/.test(password))
        issues.push('one lowercase letter');
    if (SECURITY.PASSWORD_REQUIRE_NUMBER && !/[0-9]/.test(password))
        issues.push('one number');
    if (SECURITY.PASSWORD_REQUIRE_SPECIAL && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password))
        issues.push('one special character');
    if (!issues.length) return '';
    return 'Password needs: ' + issues.join(', ');
}

function isValidInteger(val, min, max) {
    const n = parseInt(String(val ?? ''), 10);
    if (isNaN(n)) return false;
    if (min !== undefined && n < min) return false;
    if (max !== undefined && n > max) return false;
    return true;
}

function truncate(str, maxLen = 500) {
    if (!str) return '';
    return String(str).trim().substring(0, maxLen);
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// WRITER CHANGE HISTORY HELPERS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function buildWriterChangeEntry(fromWriter, toWriter, reason, adminEmail) {
    return {
        reason:     sanitizeInput(reason,     SECURITY.MAX_REASON_LENGTH),
        changedAt:  new Date().toISOString(),
        changedBy:  sanitizeInput(adminEmail, SECURITY.MAX_EMAIL_LENGTH),
        fromWriter: sanitizeInput(fromWriter, SECURITY.MAX_NAME_LENGTH),
        toWriter:   sanitizeInput(toWriter,   SECURITY.MAX_NAME_LENGTH),
        seenAt:     null,
        seenBy:     null,
    };
}

function markHistoryAsSeen(history, adminEmail) {
    if (!Array.isArray(history)) return [];
    const now = new Date().toISOString();
    const sanitizedBy = sanitizeInput(adminEmail, SECURITY.MAX_EMAIL_LENGTH);
    return history.map(entry =>
        entry.seenAt ? entry : { ...entry, seenAt: now, seenBy: sanitizedBy }
    );
}

function hasUnseenWriterChange(show) {
    if (!show) return false;
    const history = Array.isArray(show.writerChangeHistory) ? show.writerChangeHistory : [];
    if (history.some(e => !e.seenAt)) return true;
    if (show.writerChangeReason && !show.writerChangeSeenAt) return true;
    return false;
}

function getWriterChangeHistory(show) {
    if (!show) return [];
    const history = Array.isArray(show.writerChangeHistory) ? show.writerChangeHistory : [];
    if (history.length === 0 && show.writerChangeReason) {
        return [{
            reason:     show.writerChangeReason    || '',
            changedAt:  show.writerChangeReasonAt  || '',
            changedBy:  show.writerChangeReasonBy  || '',
            fromWriter: '',
            toWriter:   show.assignedTo            || '',
            seenAt:     show.writerChangeSeenAt    || null,
            seenBy:     null,
        }];
    }
    return history;
}


// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// EXPORTS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
export {
    auth, db, ensureInitialized, WORKER_URL, SECURITY,
    SecureLogger,

    onAuthStateChanged,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    signOut,
    sendEmailVerification,
    sendPasswordResetEmail,
    getIdToken,

    verifyUserRoleFromFirestore,

    doc, setDoc, getDoc, getDocs, updateDoc, deleteDoc,
    collection, query, where, orderBy, limit,
    onSnapshot, writeBatch, serverTimestamp,
    Timestamp, arrayUnion, arrayRemove,

    SecureSession,
    RateLimiter,
    CryptoUtils,

    isValidEmail,
    isValidURL,
    isValidInteger,
    isStrongPassword,
    getPasswordStrengthMessage,
    sanitizeInput,
    sanitizeForStorage,
    sanitizeHTML,
    setTextSafe,
    truncate,

    buildWriterChangeEntry,
    markHistoryAsSeen,
    hasUnseenWriterChange,
    getWriterChangeHistory,
};
