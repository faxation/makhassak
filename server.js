const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const rootDir = __dirname;
const dataDir = path.join(rootDir, "data");
const authStorePath = path.join(dataDir, "auth-store.json");
const port = Number(process.env.PORT || 3000);

const sessionCookieName = "pe_session";
const sessionDurationMs = 1000 * 60 * 60 * 24 * 7;
const otpDurationMs = 1000 * 60 * 15;
const otpAttemptLimit = 5;
const maxRequestBodyBytes = 16 * 1024;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const usernamePattern = /^[a-zA-Z0-9_.-]{3,20}$/;

const routeMap = new Map([
  ["/", "index.html"],
  ["/login", path.join("login", "index.html")],
  ["/signup", path.join("signup", "index.html")],
  ["/forgot-password", path.join("forgot-password", "index.html")],
  ["/socials", path.join("socials", "index.html")],
]);

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".woff2": "font/woff2",
};

function createEmptyAuthStore() {
  return {
    users: [],
    sessions: [],
    passwordResets: [],
  };
}

function getDefaultHeaders(extraHeaders = {}) {
  return {
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders,
  };
}

function ensureAuthStore() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (!fs.existsSync(authStorePath)) {
    fs.writeFileSync(authStorePath, JSON.stringify(createEmptyAuthStore(), null, 2));
  }
}

function normalizeAuthStore(store) {
  return {
    users: Array.isArray(store?.users) ? store.users : [],
    sessions: Array.isArray(store?.sessions) ? store.sessions : [],
    passwordResets: Array.isArray(store?.passwordResets) ? store.passwordResets : [],
  };
}

function pruneAuthStore(store) {
  const now = Date.now();

  store.sessions = store.sessions.filter((session) => Date.parse(session.expiresAt) > now);
  store.passwordResets = store.passwordResets.filter((entry) => {
    return Date.parse(entry.expiresAt) > now && Number(entry.attemptsRemaining) > 0;
  });

  return store;
}

function readAuthStore() {
  ensureAuthStore();

  try {
    const store = JSON.parse(fs.readFileSync(authStorePath, "utf8"));
    return pruneAuthStore(normalizeAuthStore(store));
  } catch (error) {
    console.error("Failed to read auth store, recreating it.", error);
    return createEmptyAuthStore();
  }
}

function writeAuthStore(store) {
  ensureAuthStore();
  fs.writeFileSync(authStorePath, JSON.stringify(pruneAuthStore(normalizeAuthStore(store)), null, 2));
}

function sendFile(filePath, response) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      response.writeHead(error.code === "ENOENT" ? 404 : 500, getDefaultHeaders({
        "Content-Type": "text/plain; charset=utf-8",
      }));
      response.end(error.code === "ENOENT" ? "Not found" : "Internal server error");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    response.writeHead(200, getDefaultHeaders({
      "Content-Type": contentTypes[ext] || "application/octet-stream",
    }));
    response.end(data);
  });
}

function sendJson(response, statusCode, payload, extraHeaders = {}) {
  response.writeHead(statusCode, getDefaultHeaders({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    ...extraHeaders,
  }));
  response.end(JSON.stringify(payload));
}

function sendAuthError(response, statusCode, message, extraHeaders = {}) {
  sendJson(response, statusCode, { message }, extraHeaders);
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendVerifyOtpPage(email, response) {
  const filePath = path.join(rootDir, "verify-otp", "index.html");

  fs.readFile(filePath, "utf8", (error, html) => {
    if (error) {
      response.writeHead(500, getDefaultHeaders({ "Content-Type": "text/plain; charset=utf-8" }));
      response.end("Internal server error");
      return;
    }

    const htmlEmail = escapeHtml(email);
    const jsonEmail = JSON.stringify(email).slice(1, -1);
    const encodedEmail = encodeURIComponent(email);

    const rendered = html
      .replaceAll("<!-- -->test@example.com<!-- -->", `<!-- -->${htmlEmail}<!-- -->`)
      .replaceAll('"test@example.com"', `"${jsonEmail}"`)
      .replaceAll("test%40example.com", encodedEmail);

    response.writeHead(200, getDefaultHeaders({ "Content-Type": "text/html; charset=utf-8" }));
    response.end(rendered);
  });
}

function toBase64Url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function createId(byteLength = 16) {
  return crypto.randomBytes(byteLength).toString("hex");
}

function createSecret(byteLength = 32) {
  return toBase64Url(crypto.randomBytes(byteLength));
}

function hashValue(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeCompare(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function hashPassword(password, salt = createSecret(16)) {
  return {
    passwordHash: crypto.scryptSync(password, salt, 64).toString("hex"),
    passwordSalt: salt,
  };
}

function verifyPassword(password, user) {
  const expectedHash = crypto.scryptSync(password, user.passwordSalt, 64).toString("hex");
  return safeCompare(user.passwordHash, expectedHash);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function normalizeName(name) {
  return String(name || "").trim().replace(/\s+/g, " ").slice(0, 120);
}

function isValidEmail(email) {
  return email.length > 3 && email.length <= 320 && emailPattern.test(email);
}

function isValidUsername(username) {
  return usernamePattern.test(username);
}

function isValidPassword(password) {
  return typeof password === "string" && password.length >= 6 && password.length <= 128;
}

function createSession(store, userId) {
  const token = createSecret(32);
  const session = {
    id: createId(),
    userId,
    tokenHash: hashValue(token),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + sessionDurationMs).toISOString(),
  };

  store.sessions.push(session);

  return { token, session };
}

function createOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function parseCookies(cookieHeader) {
  const cookies = {};

  if (!cookieHeader) {
    return cookies;
  }

  for (const segment of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = segment.trim().split("=");
    if (!rawName) {
      continue;
    }

    cookies[rawName] = decodeURIComponent(rawValue.join("="));
  }

  return cookies;
}

function getRequestOrigin(request) {
  const forwardedProto = request.headers["x-forwarded-proto"];
  const forwardedHost = request.headers["x-forwarded-host"];
  const protocol = typeof forwardedProto === "string" && forwardedProto
    ? forwardedProto.split(",")[0].trim()
    : "http";
  const host = typeof forwardedHost === "string" && forwardedHost
    ? forwardedHost.split(",")[0].trim()
    : request.headers.host;

  return host ? `${protocol}://${host}` : null;
}

function isSecureRequest(request) {
  const origin = getRequestOrigin(request);
  return Boolean(origin && origin.startsWith("https://"));
}

function isTrustedOrigin(request) {
  if (!request.headers.origin) {
    return true;
  }

  const requestOrigin = getRequestOrigin(request);

  if (!requestOrigin) {
    return false;
  }

  try {
    const originUrl = new URL(request.headers.origin);
    const requestUrl = new URL(requestOrigin);

    if (originUrl.origin === requestUrl.origin) {
      return true;
    }

    // Allow same-host HTTPS origins when TLS is terminated before Node and the proxy
    // does not forward x-forwarded-proto, causing the server to see the request as HTTP.
    return originUrl.host === requestUrl.host
      && originUrl.protocol === "https:"
      && requestUrl.protocol === "http:";
  } catch (error) {
    return false;
  }
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax"];

  if (typeof options.maxAgeSeconds === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`);
  }

  if (options.expires) {
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }

  if (options.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function setSessionCookie(response, request, token) {
  response.setHeader("Set-Cookie", serializeCookie(sessionCookieName, token, {
    maxAgeSeconds: sessionDurationMs / 1000,
    secure: isSecureRequest(request),
  }));
}

function clearSessionCookie(response, request) {
  response.setHeader("Set-Cookie", serializeCookie(sessionCookieName, "", {
    maxAgeSeconds: 0,
    expires: new Date(0),
    secure: isSecureRequest(request),
  }));
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    displayUsername: user.displayUsername,
    createdAt: user.createdAt,
  };
}

function findUserByEmail(store, email) {
  return store.users.find((user) => user.email === email);
}

function findUserByUsername(store, username) {
  return store.users.find((user) => user.username === username);
}

function findSession(request, store) {
  const token = parseCookies(request.headers.cookie)[sessionCookieName];

  if (!token) {
    return null;
  }

  const tokenHash = hashValue(token);
  const session = store.sessions.find((entry) => safeCompare(entry.tokenHash, tokenHash));

  if (!session) {
    return null;
  }

  const user = store.users.find((entry) => entry.id === session.userId);

  if (!user) {
    return null;
  }

  return { session, user, token };
}

function isAllowedRedirectPath(pathname) {
  return pathname === "/" || pathname === "/verify-otp" || routeMap.has(pathname);
}

function getSafeRedirectUrl(request, callbackURL) {
  if (typeof callbackURL !== "string" || !callbackURL.trim()) {
    return "/";
  }

  const requestOrigin = getRequestOrigin(request) || "http://localhost";

  try {
    const url = new URL(callbackURL, requestOrigin);
    return url.origin === requestOrigin && isAllowedRedirectPath(url.pathname)
      ? `${url.pathname}${url.search}`
      : "/";
  } catch (error) {
    return "/";
  }
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;

    request.on("data", (chunk) => {
      if (settled) {
        return;
      }

      size += chunk.length;

      if (size > maxRequestBodyBytes) {
        settled = true;
        request.resume();
        reject({ statusCode: 413, message: "Request body too large" });
        return;
      }

      chunks.push(chunk);
    });

    request.on("end", () => {
      if (settled) {
        return;
      }

      if (chunks.length === 0) {
        resolve({});
        return;
      }

      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));

        if (!body || typeof body !== "object" || Array.isArray(body)) {
          throw new Error("Body must be a JSON object.");
        }

        resolve(body);
      } catch (error) {
        reject({ statusCode: 400, message: "Invalid JSON payload" });
      }
    });

    request.on("error", () => {
      if (!settled) {
        reject({ statusCode: 400, message: "Failed to read request body" });
      }
    });
  });
}

async function handleGetSession(request, response) {
  const store = readAuthStore();
  const auth = findSession(request, store);

  if (!auth) {
    if (parseCookies(request.headers.cookie)[sessionCookieName]) {
      clearSessionCookie(response, request);
      sendJson(response, 200, null);
      return;
    }

    sendJson(response, 200, null);
    return;
  }

  sendJson(response, 200, {
    session: {
      id: auth.session.id,
      expiresAt: auth.session.expiresAt,
    },
    user: publicUser(auth.user),
  });
}

async function handleUsernameAvailability(request, response) {
  const body = request.method === "POST" ? await readJsonBody(request) : {};
  const username = normalizeUsername(body.username || "");

  if (!isValidUsername(username)) {
    sendAuthError(response, 400, "Invalid username format");
    return;
  }

  const store = readAuthStore();
  sendJson(response, 200, {
    available: !findUserByUsername(store, username),
  });
}

async function handleSignup(request, response) {
  const body = await readJsonBody(request);
  const email = normalizeEmail(body.email);
  const username = normalizeUsername(body.username);
  const displayUsername = normalizeUsername(body.displayUsername || body.username);
  const name = normalizeName(body.name);
  const password = String(body.password || "");

  if (!name) {
    sendAuthError(response, 400, "Please enter your first and last name");
    return;
  }

  if (!isValidEmail(email)) {
    sendAuthError(response, 400, "Please enter a valid email address");
    return;
  }

  if (!isValidUsername(username) || !isValidUsername(displayUsername)) {
    sendAuthError(response, 400, "Invalid username format");
    return;
  }

  if (!isValidPassword(password)) {
    sendAuthError(response, 400, "Password must be between 6 and 128 characters");
    return;
  }

  const store = readAuthStore();

  if (findUserByEmail(store, email)) {
    sendAuthError(response, 409, "An account with this email already exists");
    return;
  }

  if (findUserByUsername(store, username)) {
    sendAuthError(response, 409, "Username is already taken");
    return;
  }

  const { passwordHash, passwordSalt } = hashPassword(password);
  const user = {
    id: createId(),
    email,
    name,
    username,
    displayUsername,
    passwordHash,
    passwordSalt,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  store.users.push(user);

  const { token, session } = createSession(store, user.id);
  writeAuthStore(store);
  setSessionCookie(response, request, token);

  sendJson(response, 200, {
    session: {
      id: session.id,
      expiresAt: session.expiresAt,
    },
    user: publicUser(user),
    url: getSafeRedirectUrl(request, body.callbackURL),
  });
}

async function handleSignin(request, response, identifierType) {
  const body = await readJsonBody(request);
  const password = String(body.password || "");

  if (!isValidPassword(password)) {
    sendAuthError(response, 401, "Wrong email/username or password");
    return;
  }

  const store = readAuthStore();
  const identifier = identifierType === "email"
    ? normalizeEmail(body.email)
    : normalizeUsername(body.username);
  const user = identifierType === "email"
    ? findUserByEmail(store, identifier)
    : findUserByUsername(store, identifier);

  if (!user || !verifyPassword(password, user)) {
    sendAuthError(response, 401, "Wrong email/username or password");
    return;
  }

  const { token } = createSession(store, user.id);
  writeAuthStore(store);
  setSessionCookie(response, request, token);

  sendJson(response, 200, {
    redirect: true,
    url: getSafeRedirectUrl(request, body.callbackURL),
    user: publicUser(user),
  });
}

async function handleSignout(request, response) {
  const store = readAuthStore();
  const auth = findSession(request, store);

  if (auth) {
    store.sessions = store.sessions.filter((session) => session.id !== auth.session.id);
    writeAuthStore(store);
  }

  clearSessionCookie(response, request);
  sendJson(response, 200, { success: true });
}

async function handleSendVerificationOtp(request, response) {
  const body = await readJsonBody(request);
  const email = normalizeEmail(body.email);
  const type = String(body.type || "");

  if (type !== "forget-password") {
    sendAuthError(response, 400, "Unsupported OTP type");
    return;
  }

  if (!isValidEmail(email)) {
    sendAuthError(response, 400, "Please enter a valid email address");
    return;
  }

  const store = readAuthStore();
  const user = findUserByEmail(store, email);

  if (user) {
    const otp = createOtp();

    store.passwordResets = store.passwordResets.filter((entry) => !(entry.email === email && entry.type === type));
    store.passwordResets.push({
      id: createId(),
      email,
      otpHash: hashValue(otp),
      type,
      attemptsRemaining: otpAttemptLimit,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + otpDurationMs).toISOString(),
    });
    writeAuthStore(store);

    console.log(`[auth] Password reset OTP for ${email}: ${otp}`);
  }

  // Do not reveal whether the email exists to avoid user enumeration.
  sendJson(response, 200, { success: true });
}

async function handleResetPassword(request, response) {
  const body = await readJsonBody(request);
  const email = normalizeEmail(body.email);
  const otp = String(body.otp || "").trim();
  const password = String(body.password || "");

  if (!isValidEmail(email)) {
    sendAuthError(response, 400, "Please enter a valid email address");
    return;
  }

  if (!/^\d{6}$/.test(otp)) {
    sendAuthError(response, 400, "Invalid or expired OTP");
    return;
  }

  if (!isValidPassword(password)) {
    sendAuthError(response, 400, "Password must be between 6 and 128 characters");
    return;
  }

  const store = readAuthStore();
  const user = findUserByEmail(store, email);
  const resetEntry = store.passwordResets.find((entry) => entry.email === email && entry.type === "forget-password");

  if (!user || !resetEntry) {
    sendAuthError(response, 400, "Invalid or expired OTP");
    return;
  }

  if (!safeCompare(resetEntry.otpHash, hashValue(otp))) {
    resetEntry.attemptsRemaining = Number(resetEntry.attemptsRemaining) - 1;
    store.passwordResets = store.passwordResets.filter((entry) => entry.attemptsRemaining > 0);
    writeAuthStore(store);
    sendAuthError(response, 400, "Invalid or expired OTP");
    return;
  }

  const { passwordHash, passwordSalt } = hashPassword(password);
  user.passwordHash = passwordHash;
  user.passwordSalt = passwordSalt;
  user.updatedAt = new Date().toISOString();

  store.passwordResets = store.passwordResets.filter((entry) => entry.id !== resetEntry.id);
  store.sessions = store.sessions.filter((session) => session.userId !== user.id);
  writeAuthStore(store);
  clearSessionCookie(response, request);

  sendJson(response, 200, { success: true });
}

async function handleAuthRequest(request, response, normalizedPath) {
  if (!normalizedPath.startsWith("/api/auth")) {
    return false;
  }

  if (!["GET", "POST"].includes(request.method || "")) {
    sendAuthError(response, 405, "Method not allowed");
    return true;
  }

  if (request.method === "POST" && !isTrustedOrigin(request)) {
    sendAuthError(response, 403, "Invalid request origin");
    return true;
  }

  const authPath = normalizedPath.slice("/api/auth".length) || "/";

  try {
    switch (authPath) {
      case "/get-session":
        if (request.method !== "GET") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleGetSession(request, response);
        return true;

      case "/is-username-available":
        await handleUsernameAvailability(request, response);
        return true;

      case "/sign-up/email":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleSignup(request, response);
        return true;

      case "/sign-in/email":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleSignin(request, response, "email");
        return true;

      case "/sign-in/username":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleSignin(request, response, "username");
        return true;

      case "/sign-out":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleSignout(request, response);
        return true;

      case "/email-otp/send-verification-otp":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleSendVerificationOtp(request, response);
        return true;

      case "/email-otp/reset-password":
        if (request.method !== "POST") {
          sendAuthError(response, 405, "Method not allowed");
          return true;
        }
        await handleResetPassword(request, response);
        return true;

      default:
        sendAuthError(response, 404, "Not found");
        return true;
    }
  } catch (error) {
    if (error?.statusCode) {
      sendAuthError(response, error.statusCode, error.message);
      return true;
    }

    console.error("Unhandled auth error", error);
    sendAuthError(response, 500, "Internal server error");
    return true;
  }
}

http
  .createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const pathname = decodeURIComponent(url.pathname);
    const normalizedPath = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;

    if (await handleAuthRequest(request, response, normalizedPath)) {
      return;
    }

    if (normalizedPath === "/verify-otp") {
      const email = url.searchParams.get("email");

      if (email) {
        sendVerifyOtpPage(email, response);
      } else {
        sendFile(path.join(rootDir, "verify-otp", "invalid.html"), response);
      }
      return;
    }

    if (routeMap.has(normalizedPath)) {
      sendFile(path.join(rootDir, routeMap.get(normalizedPath)), response);
      return;
    }

    const requestedPath = path.normalize(path.join(rootDir, pathname.replace(/^\/+/, "")));
    const relativePath = path.relative(rootDir, requestedPath);

    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
      response.writeHead(403, getDefaultHeaders({ "Content-Type": "text/plain; charset=utf-8" }));
      response.end("Forbidden");
      return;
    }

    fs.stat(requestedPath, (error, stats) => {
      if (error) {
        response.writeHead(404, getDefaultHeaders({ "Content-Type": "text/plain; charset=utf-8" }));
        response.end("Not found");
        return;
      }

      if (stats.isDirectory()) {
        sendFile(path.join(requestedPath, "index.html"), response);
        return;
      }

      sendFile(requestedPath, response);
    });
  })
  .listen(port, () => {
    console.log(`Purple Edge mirror running at http://localhost:${port}`);
  });
