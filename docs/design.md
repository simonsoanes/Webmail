# Nullify.WebMail — Design Document

> **Architecture revision (2026-10-23).** The original plan below described a
> two-project split (ASP.NET Core host + standalone Blazor WebAssembly client).
> The app is now a **single-project Blazor Server** application:
>
> - `Components/App.razor` is the HTML shell; `<Routes @rendermode="InteractiveServer" />`
>   makes the whole UI interactive, and `_framework/blazor.web.js` is referenced
>   explicitly (the framework does not inject it).
> - Components call services **in-process** through `ApiService` (a facade over
>   `MailService`, EF, and the Sieve client). The earlier HTTP-loopback design
>   could never work: a server-side `HttpClient` cannot carry or set the
>   browser's auth cookie.
> - Login/setup/logout are **browser-side `fetch` calls** (`wwwroot/js/auth.js`)
>   to JSON endpoints, so `Set-Cookie` lands in the browser jar; the page then
>   force-reloads to start an authenticated circuit.
> - `UserSession` bridges auth into circuits: credentials are captured from the
>   request cookie during prerender and restored inside the circuit via
>   `PersistentComponentState` (DataProtection-encrypted blob).
> - First-run bootstrap: with zero users, `/` renders the Setup page, which
>   authenticates against the *submitted* IMAP host, creates the admin user and
>   a `Domain` mapping in one step.
> - Domain mapping: `Domain` table routes logins per email domain to specific
>   IMAP/SMTP/Sieve servers; `restrict_domains` admin setting limits logins to
>   configured domains. The first user to log in becomes admin.
>
> The sections below remain valid for the data model, protocols, and phasing;
> read "Blazor WebAssembly" as "Blazor Server" throughout.

## Purpose

A self-hosted webmail client.  Users sign in with their IMAP credentials; the
server proxies IMAP/SMTP/ManageSieve/CalDAV/CardDAV traffic and stores only
preferences and a lightweight folder cache in SQLite.  The browser UI is a
Blazor WebAssembly app that handles message rendering, composition, and
OpenPGP operations locally.  No third-party JavaScript libraries and minimal
NuGet packages — the same philosophy as Nullify.CalDav.

## What already exists

- **Nullify.CalDav** — a CalDAV/CardDAV/SyncML server with a hand‑rolled IMAP
  authenticator (`Services/Imap.cs`).  Patterns to reuse: ASP.NET Core Razor
  Pages host, SQLite + EF Core, cookie auth, `ServerSettings` key‑value
  store, `WriteGate`, minimal CSS with light/dark, forward‑header trust,
  `Program.cs` structure.

## Data model (server-side SQLite)

### `User` (no password hash)
| Column | Type | Notes |
|---|---|---|
| Id | int | PK |
| Username | string(64) NOCASE | Unique login name (e.g. email or IMAP login) |
| DisplayName | string | |
| Email | string(256) | Primary email address |
| ImapHost | string? | Per‑user override |
| ImapPort | int? | |
| ImapSecurity | MailSecurity? | Tls / StartTls / None |
| CreatedUtc | DateTime | |
| LastLoginUtc | DateTime? | |

No `PasswordHash` — authentication is always delegated to the IMAP server.

### `UserPreference` — key‑value scoped to a user
| Column | Type |
|---|---|
| Id | int |
| UserId | int FK→User |
| Key | string |
| Value | string? |

Examples: `compose.format` = `html`, `folders.expanded` = `INBOX,Sent`, `pgp.defaultKey`.

### `ImapFolderCache` — lightweight mirror of IMAP folders
| Column | Type |
|---|---|
| Id | int |
| UserId | int FK→User |
| Name | string | Full IMAP name (e.g. `INBOX.Archive.2024`) |
| Attributes | string | Comma‑separated: `\HasChildren,\Noselect` |
| TotalMessages | int | |
| UnreadMessages | int | |
| LastSyncUtc | DateTime | |

### `SieveScript` — cached copy of a ManageSieve script
| Column | Type |
|---|---|
| Id | int |
| UserId | int FK→User |
| Name | string | Script name (e.g. `main`) |
| IsActive | bool | |
| Content | string | The Sieve text |
| ETag | string? | Server ETag for conflict detection |
| LastSyncUtc | DateTime | |

### `SessionCredential` — encrypted IMAP/SMTP credential in server memory
Stored in ASP.NET Core `IDataProtector`‑protected cookies, not in the
database.  The cookie contains the IMAP host, port, security, login, and an
encrypted password.  On each request the server decrypts it, opens (or
reuses) an IMAP connection pool entry, and proxies the operation.

### Connection pool (in‑memory singleton)
A `ConcurrentDictionary<string, ImapConnectionPool>` keyed by connection
fingerprint.  Each pool holds up to 3 idle connections with a 5‑minute TTL.
Commands are serialised per connection; IMAP IDLE runs on a dedicated
connection.

## Backend API surface

The server exposes a JSON REST API consumed by the Blazor WASM client.
All endpoints require cookie authentication.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/login` | IMAP login, sets auth cookie |
| POST | `/api/auth/logout` | Clears cookie, tears down connections |
| GET | `/api/mail/folders` | List folders (from cache, async refresh) |
| GET | `/api/mail/folders/{encoded}/messages?page=&sort=` | List message envelopes |
| GET | `/api/mail/folders/{encoded}/messages/{uid}` | Full message source |
| GET | `/api/mail/folders/{encoded}/messages/{uid}/body` | Parsed body parts |
| GET | `/api/mail/folders/{encoded}/messages/{uid}/attachments/{part}` | Attachment download |
| PUT | `/api/mail/folders/{encoded}/messages/{uid}/flags` | Set/clear flags |
| POST | `/api/mail/folders/{encoded}/messages/{uid}/move` | Move to another folder |
| DELETE | `/api/mail/folders/{encoded}/messages/{uid}` | Delete (move to Trash) |
| POST | `/api/mail/send` | Send via SMTP + save to Sent |
| POST | `/api/mail/folders` | Create folder |
| DELETE | `/api/mail/folders/{encoded}` | Delete folder |
| PUT | `/api/mail/folders/{encoded}` | Rename folder |
| GET | `/api/sieve/scripts` | List Sieve scripts |
| GET | `/api/sieve/scripts/{name}` | Get script content |
| PUT | `/api/sieve/scripts/{name}` | Create/update script |
| DELETE | `/api/sieve/scripts/{name}` | Delete script |
| PUT | `/api/sieve/scripts/{name}/activate` | Set active |
| GET | `/api/prefs` | All preferences for current user |
| PUT | `/api/prefs/{key}` | Set a single preference |
| GET | `/api/session` | Current user info, capabilities |

## Blazor WASM frontend

### Layout (three‑column on desktop, single‑column on mobile)

```
┌──────────┬──────────────────┬──────────────────┐
│ Folders  │ Message list     │ Preview /        │
│          │ (envelope rows)  │ Compose          │
│          │                  │                  │
│ Cal/Card │                  │ (isolated        │
│ (tabs)   │                  │  iframe for      │
│          │                  │  HTML mail)      │
└──────────┴──────────────────┴──────────────────┘
```

- **Column 1**: Folder tree, with bottom tabs for Calendar / Contacts.
- **Column 2**: Message list with search, sort, pagination.
- **Column 3**: Context‑sensitive — message preview, compose form, settings.

Mobile: single column with a bottom tab bar to switch between Folders,
Message List, and Preview/Compose.

### Message preview isolation

HTML messages are not sanitised; they are rendered as-is in a **sandboxed
`<iframe srcdoc="…">`** (`MessagePreview.razor`, `BuildFrameDoc`) with:

```
sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
```

Two independent layers keep script out, and each blocks it on its own:

- **No `allow-scripts`**: inline scripts, event handlers, `javascript:` URLs
  and nested frames (which inherit the sandbox) never run.  No `allow-forms`
  either, so forms cannot submit; no `allow-top-navigation`, so the message
  cannot navigate the app away.
- **A CSP `<meta>` in the frame's `<head>`**: `default-src 'none'` blocks
  scripts, plugins (`object`/`embed`) and frames, and stops `javascript:`
  links even in a popup.  Remote images, CSS, fonts and media are blocked
  until the user clicks to allow them; that relaxes only those directives
  and loads them directly from the sender's servers (they are not proxied).
  A CSP `<meta>` in the message body is ignored, so a message cannot loosen
  it.

**Why `allow-same-origin` is there:** the parent page sizes the frame to
its content by reading `frame.contentDocument` (`nullifyApp.fitFrame` in
`app.js`), which needs same-origin access; without scripts in the frame
there is no way for it to report its own height.  The cost is that the
frame shares the app's origin, so **`allow-scripts` must never be added**:
together with `allow-same-origin` it would let any message escape the
sandbox and reach the session, storage and in-browser PGP keys, leaving
the CSP as the only barrier.

`allow-popups` and `allow-popups-to-escape-sandbox` let links open in a
new tab (`<base target="_blank">`) as normal, unsandboxed pages.  Links get
the browser's implicit `noopener`, and `<meta name="referrer"
content="no-referrer">` plus `referrerpolicy="no-referrer"` keep the
webmail URL out of the Referer header.

### Sender verification (DKIM / SPF)

`SenderAuth` reads the `Authentication-Results` and `Received-SPF` headers the
user's own mail server wrote, and the preview shows a small shield beside the
sender (verified) or a warning (not verified).  Senders can write those headers
too, so only ones above the hop where the message arrived from the internet
(the topmost `Received` with a public client IP) are trusted; anything below
was supplied by the sender.  An `Authentication-Results` header must also name
one of the server's own `Received` hops, or match `Imap:AuthServId` when set.

"Verified" means a DKIM or SPF pass *for the From address's domain*: a pass
for some other domain does not vouch for the sender shown.  More than one From
header, a DMARC fail, or a "pass" in the server's name found below the ingress
hop (a forgery attempt) always gives the warning.  Nothing is shown at all for
local mail, authenticated submissions, or a server that records no results, so
missing headers never look like a pass or a failure.

### OpenPGP

- Keys are stored in the browser's **IndexedDB** (encrypted with a user
  passphrase, or unprotected — user's choice).
- Decryption happens in **WebAssembly** (a .NET OpenPGP library compiled to
  WASM, or a minimal C library via P/Invoke).  The decrypted content never
  leaves the browser.
- Signing and encryption likewise happen client‑side before the message is
  sent to the SMTP endpoint.
- Key generation, import, export, and key server lookup are all client‑side.

### Editors

- **Plain text**: a `<textarea>` with monospace font.
- **HTML**: a contenteditable `<div>` with a minimal toolbar (bold, italic,
  link, quote, list).  Output is cleaned to a safe subset before sending.
- Both editors show the raw message in reply/forward scenarios, with quoted
  text collapsed by default.

### Sieve editor

A text editor with syntax highlighting for Sieve scripts, plus a test
runner that evaluates a script against sample messages.

## CalDAV / CardDAV integration

The server proxies CalDAV/CardDAV requests to the configured DAV server
(same host as IMAP by default, overridable).  The Blazor client calls the
server's proxy endpoints, which add the user's credential and forward the
request.  Calendar and contact data is rendered in the client (no separate
DAV server — we're a *client*, unlike Nullify.CalDav which *is* the server).

Alternatively, for v1, use the existing Nullify.CalDav server as the DAV
backend and just point the webmail at it.

### Tasks and notes

Tasks are VTODOs and notes are VJOURNALs, stored in the same CalDAV account
as the calendar. Discovery records each collection's
`supported-calendar-component-set`, so one PROPFIND finds the calendars,
task lists and notes lists together (a collection that advertises no set
accepts everything). Items are listed with a `calendar-query` REPORT
filtered on the component.

Writes follow the event rules: an edit starts from a fresh GET and rewrites
only the properties the editor owns (alarms, categories, X- properties and
progress such as `IN-PROCESS` are kept), and the PUT carries `If-Match`
with the ETag the user opened, so a change made elsewhere is reported
rather than overwritten. Ticking a task changes only `STATUS`, `COMPLETED`
and `PERCENT-COMPLETE`. A repeating task is edited and completed as one
item; the next occurrence is not generated.

Many servers' default calendars accept only VEVENT and VTODO, so the Notes
and Tasks pages offer to create a collection with MKCALENDAR in the
calendar home when there is nowhere to keep them.

## IMAP IDLE

The server maintains one long‑lived IMAP connection per logged‑in user for
IDLE.  When the server sees an `EXISTS` or `RECENT` untagged response during
IDLE, it sends a Server‑Sent Events (SSE) notification to the Blazor client
(`/api/events`).  The client then refreshes the affected folder.

## Phasing

### Phase 1 — Core mail (this PR)
- [x] Project scaffold, SQLite schema, cookie auth via IMAP
- [ ] Full IMAP client (folder list, message fetch, flags, move, delete)
- [ ] SMTP client for sending
- [ ] REST API
- [ ] Blazor WASM shell with login → folder list → message list → preview
- [ ] Plain‑text compose and reply
- [ ] IMAP IDLE + SSE notifications
- [ ] Mobile‑responsive layout

### Phase 2 — Rich composition & PGP
- [ ] HTML editor
- [ ] OpenPGP: key management, decrypt, sign, encrypt
- [ ] Attachment upload/download
- [ ] Isolated iframe preview

### Phase 3 — Sieve, Calendar, Contacts
- [ ] ManageSieve client + editor UI
- [ ] CalDAV/CardDAV proxy + calendar/contacts views
- [ ] Search (server‑side IMAP SEARCH)

### Phase 4 — Polish
- [ ] Offline cache (IndexedDB for folders/messages)
- [ ] Address autocomplete from contacts
- [ ] Keyboard shortcuts
- [ ] Push notifications (Web Push)

## Risks / limitations

1. **IMAP connection state**: Holding a connection pool server‑side means
   the app is stateful — it won't scale horizontally without sticky sessions
   or a shared session store.  For a single‑user/small‑team deployment this
   is fine and matches CalDav's pattern.

2. **Blazor WASM payload**: The .NET runtime downloaded to the browser is
   ~2 MB compressed.  Acceptable for a webmail client that is used
   repeatedly; first‑load cost is amortised.

3. **OpenPGP in WASM**: .NET OpenPGP libraries (e.g. BouncyCastle) may not
   trivially compile to WASM.  Fallback: compile a minimal C OpenPGP library
   (GPGME or rnp) to WASM, or use a managed implementation that AOT‑compiles.

4. **No offline mode in v1**: IMAP requires a live connection.  Phase 4
   would add local caching.

5. **CalDAV/CardDAV**: If no DAV server is available, these features degrade
   gracefully (hidden tabs).

## Tech stack

| Layer | Technology |
|---|---|
| Runtime | .NET 10 |
| Server | ASP.NET Core (Razor Pages host + API controllers) |
| Frontend | Blazor WebAssembly (standalone) |
| Database | SQLite via EF Core |
| Auth | ASP.NET Core cookie auth, IMAP password check |
| IMAP/SMTP/ManageSieve | Hand‑rolled clients (extend Nullify.CalDav `ImapAuthenticator`) |
| OpenPGP | Client‑side WASM (BouncyCastle or similar) |
| Testing | MSTest + Microsoft.AspNetCore.Mvc.Testing |
| CSS | Hand‑written, light/dark, mobile‑first (reuse CalDav palette) |