# Website Context & Directives

> **IMPORTANT FOR AI ASSISTANTS:** Read this file and `README.md` at the start of every new chat or editor session. Do not skip this step. These files contain critical context about the project's state, conventions, and history.

## Purpose

This document serves as the living record of all directives, design decisions, and changes made to the Makhassak (Purple Edge) website. It ensures continuity across chat sessions and editors.

---

## Directives

_Persistent rules and preferences that should be followed in all future work._

1. **Always read `README.md` and `WEBSITE-CONTEXT.md` first** before making any changes to the project.
2. **Log all meaningful changes** to the Change Log section below with date and description.
3. **Do not introduce build tools or frameworks** unless explicitly requested — the project is intentionally framework-free on the server side.
4. **Preserve the existing routing structure** in `server.js` when adding new pages.

---

## Design Decisions

_Key architectural and design choices and their reasoning._

| Decision | Reasoning |
|----------|-----------|
| Vanilla Node.js server (no Express) | Keeps dependencies minimal; the server only serves static files and one dynamic route (`/verify-otp`) |
| Pre-built HTML pages | Pages are exported/built externally and dropped into the project as static files |
| `_next/` directory for assets | Assets follow Next.js export conventions from the original build source |
| OTP email templating in `server.js` | The verify-otp page needs the email address injected server-side via query param |

---

## Change Log

_Reverse-chronological record of changes. Add new entries at the top._

| Date       | Change | Details |
|------------|--------|---------|
| 2026-04-03 | Initial documentation | Created `README.md` and `WEBSITE-CONTEXT.md` to track project context and changes |
