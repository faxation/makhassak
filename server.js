const http = require("http");
const fs = require("fs");
const path = require("path");

const rootDir = __dirname;
const port = Number(process.env.PORT || 3000);

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

function sendFile(filePath, response) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      response.writeHead(error.code === "ENOENT" ? 404 : 500, {
        "Content-Type": "text/plain; charset=utf-8",
      });
      response.end(error.code === "ENOENT" ? "Not found" : "Internal server error");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    response.writeHead(200, {
      "Content-Type": contentTypes[ext] || "application/octet-stream",
    });
    response.end(data);
  });
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
      response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
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

    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end(rendered);
  });
}

http
  .createServer((request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const pathname = decodeURIComponent(url.pathname);
    const normalizedPath = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;

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

    if (!requestedPath.startsWith(rootDir)) {
      response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Forbidden");
      return;
    }

    fs.stat(requestedPath, (error, stats) => {
      if (error) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
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
