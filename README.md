# Makhassak (Purple Edge)

> **IMPORTANT FOR AI ASSISTANTS:** At the start of every new chat or editor session, read this `README.md` and `WEBSITE-CONTEXT.md` in full before making any changes. These files are the source of truth for project context, conventions, and change history.

## Overview

Makhassak is a static website served via a lightweight Node.js HTTP server. The project contains multiple HTML pages for authentication flows and social links.

## Tech Stack

- **Server:** Node.js (vanilla `http` module, no frameworks)
- **Frontend:** Static HTML pages (pre-built, located in the `_next/` directory and page folders)
- **Styling:** Tailwind CSS / inline styles (bundled in HTML)
- **No build step required** — pages are served as-is

## Project Structure

```
Purple Edge Copy/
├── _next/              # Static assets (CSS, JS, media)
├── forgot-password/    # Forgot password page
│   └── index.html
├── login/              # Login page
│   └── index.html
├── signup/             # Signup page
│   └── index.html
├── socials/            # Social links page
│   └── index.html
├── verify-otp/         # OTP verification page
│   ├── index.html
│   └── invalid.html
├── icon.svg            # Site icon
├── index.html          # Homepage / landing page
├── package.json        # Project metadata
├── server.js           # Node.js HTTP server
├── README.md           # This file
└── WEBSITE-CONTEXT.md  # Directives, decisions, and change log
```

## Running Locally

```bash
npm start
# Server runs at http://localhost:3000
```

You can also set a custom port:

```bash
PORT=8080 npm start
```

## Routes

| Path               | File                        | Notes                              |
|--------------------|-----------------------------|------------------------------------|
| `/`                | `index.html`                | Landing page                       |
| `/login`           | `login/index.html`          | Login page                         |
| `/signup`          | `signup/index.html`         | Signup page                        |
| `/forgot-password` | `forgot-password/index.html`| Password reset request             |
| `/socials`         | `socials/index.html`        | Social media links                 |
| `/verify-otp`      | `verify-otp/index.html`     | OTP verification (requires `?email=`) |

## Change Log

All changes, decisions, and directives are documented in [`WEBSITE-CONTEXT.md`](WEBSITE-CONTEXT.md).
