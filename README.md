# Nullify.WebMail

A self-hosted **webmail client** for your existing IMAP/SMTP server, with calendar, contacts, files, server-side filters and **OpenPGP**. It is built on .NET 10 (Blazor Server) and SQLite (or PostgreSQL), and is designed to run in Docker on Linux behind a reverse proxy such as Caddy.

- **Mail** over IMAP and SMTP: folders, search, flags, move and archive, attachments, HTML and plain-text compose, reply and forward
- **Safe message display**: HTML mail is rendered in a sandboxed iframe, with remote images blocked until you allow them
- **OpenPGP** in the browser: key generation, import and export, encrypt, decrypt, sign and verify, with optional unlock by a security key (WebAuthn PRF). The OpenPGP cryptography runs in the browser, and private keys are only stored in protected form.
- **Calendar and contacts** from any CalDAV/CardDAV server, with recipient autocomplete from your address books
- **Tasks and notes** kept on the same CalDAV server (as VTODOs and VJOURNALs), so they sync with other CalDAV apps. If none of your calendars accept them, the app can create a task list or notes list for you
- **Files** from a WebDAV server
- **Filters** via ManageSieve, with a Sieve script editor
- **Multi-domain**: each email domain can be routed to its own IMAP, SMTP and Sieve servers; administrators can restrict sign-in to configured domains
- **No password database**: users sign in with their mail credentials, which are checked against the IMAP server and then held only in server memory for the session. The browser's cookie carries just a random session key.
- **Sign in from your phone**: on a computer you don't fully trust, scan a QR code and type the password on your phone instead. The computer gets a short-lived session that the phone can end ([design](docs/qr-passkey-signin.md)).
- **Passkeys**: sign in with a fingerprint, face, PIN or security key instead of the password. The passkey also unlocks the mail password, which is stored encrypted with a key derived from the passkey (WebAuthn PRF), so the server can't read it between sign-ins. A passkey on your phone can also approve signing in a computer by QR code ([design](docs/qr-passkey-signin.md)).
- **I trust this computer**: on your own computer, tick it at sign-in to stay signed in for 30 days, even after the server restarts. The browser keeps the password in a cookie only the server can decrypt; sign out, or remove the computer in Settings, to end it.
- **OpenPGP passphrases never reach the server**, and secret keys are only ever decrypted in the browser.
- Light and dark themes, keyboard shortcuts, mobile-friendly layout
- Only Microsoft packages are used on the server, and no third-party JavaScript libraries in the browser

## Quick start (Docker + Caddy)

```bash
cp .env.example .env        # set WEBMAIL_HOST
docker compose up -d --build
```

The compose file runs the app and [Caddy](https://caddyserver.com) with automatic HTTPS ([Caddyfile](Caddyfile)). The app port is not published; only Caddy listens on 80/443.

Open `https://<WEBMAIL_HOST>/`. On first start, the **setup page** asks for your IMAP (and optionally SMTP and Sieve) server and signs you in against it. That account becomes the first administrator, and the server becomes the mapping for your email domain. **Complete setup before the site is reachable by anyone else**: until then, whoever opens the page first becomes the administrator.

Sessions live in the app's memory, so restarting or updating the container signs everyone out. For the same reason, run a single instance, or use sticky sessions if you put several behind a load balancer.

Everything is stored in the `webmail-data` volume (`nullify-webmail.db` plus the `keys/` folder used to encrypt cookies and stored secrets; back both up together). The container runs as the non-root `app` user (UID 1654). When bind-mounting a host directory, make it writable for that UID.

### Reverse proxy

The UI is a Blazor Server app, so the proxy must pass **WebSockets** through. Caddy does this automatically. With nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;   # map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_read_timeout 1h;
    client_max_body_size 64m;
}
```

`X-Forwarded-*` headers are only trusted from loopback unless you set `ReverseProxy__KnownProxies` or `ReverseProxy__KnownNetworks`. The compose file trusts the private Docker ranges. Mail credentials are sent at sign-in, so never expose the app over plain HTTP.

### Running locally

```bash
dotnet run --project src/Nullify.WebMail
```

The app listens on `http://localhost:5000`. Data is written to `src/Nullify.WebMail/data` unless `Storage__DataDirectory` is set; that folder is git-ignored.

## Configuration

All settings can be provided as environment variables (`Section__Key`) or in `appsettings.json`. The server defaults below are used for domains that have no mapping of their own. Domain mappings and other runtime settings are edited by administrators in the app and stored in the database.

| Variable | Default | Purpose |
|----------|---------|---------|
| `Storage__DataDirectory` | `/data` in Docker | Location of the SQLite database and key ring |
| `Database__Provider` | `Sqlite` | `Sqlite`, or `PostgreSql` to store data in PostgreSQL (the key ring stays in the data directory) |
| `Database__ConnectionString` | | PostgreSQL connection string, e.g. `Host=db;Database=webmail;Username=webmail;Password=...`; required with `PostgreSql` |
| `PublicUrl` | *(empty)* | Public base URL of the site |
| `Imap__Host`, `Imap__Port`, `Imap__Security` | `993`, `Tls` | Default IMAP server (`Tls`, `StartTls` or `None`) |
| `Imap__AllowInvalidCertificates` | `false` | Accept self-signed IMAP certificates |
| `Imap__AuthServId` | | The name your mail server writes in `Authentication-Results` (comma-separated if several). Optional: when unset, results are trusted only if they name one of the server's own `Received` hops |
| `Smtp__Host`, `Smtp__Port`, `Smtp__Security` | `587`, `StartTls` | Default SMTP server |
| `Sieve__Host`, `Sieve__Port` | `4190` | Default ManageSieve server |
| `CalDav__Url`, `CardDav__Url` | | Default CalDAV / CardDAV server |
| `ConnectionPool__Size` | `3` | IMAP connections kept per signed-in user |
| `ConnectionPool__IdleMinutes` | `5` | Idle time before pooled connections close |
| `ReverseProxy__Enabled` | `true` | Process `X-Forwarded-*` headers |
| `ReverseProxy__KnownNetworks` | loopback | Comma-separated CIDR ranges of trusted proxies |
| `ReverseProxy__KnownProxies` | | Comma-separated trusted proxy IPs |
| `ReverseProxy__TrustAll` | `false` | Trust forwarded headers from any address |
| `ReverseProxy__ForwardLimit` | `1` | Number of proxy hops to process |
| `PathBase` | | Serve under a sub-path, e.g. `/webmail` |
| `QrLogin__SessionHours` | `8` | Lifetime of a session signed in from a phone by QR code (0.25–24) |
| `TrustedDevice__Days` | `30` | How long a trusted computer stays signed in without being used (1–365) |
| `Kestrel__Endpoints__Http__Url` | `http://+:8080` in Docker | Listening address |

Any standards-compliant CalDAV/CardDAV server works as the calendar, tasks, notes and contacts backend, for example Nullify.CalDav. Notes need a calendar collection that accepts VJOURNAL; some servers' default calendars only take events and tasks, in which case the Notes page offers to create one (MKCALENDAR).

## Development

```bash
dotnet test                                   # unit + integration tests
cd tests/pgp && npm ci && npm test            # OpenPGP interop tests (needs GnuPG 2.2+)
```

The OpenPGP interop tests check the browser engine in `wwwroot/js/pgp` against GnuPG and OpenPGP.js. OpenPGP.js is a test-only dependency and is not shipped.

```bash
docker build --target test .                  # .NET tests in the SDK image
docker build --target test-pgp .              # OpenPGP interop tests with Node and GnuPG
docker build -t nullify-webmail .             # runtime image
```

```
src/Nullify.WebMail
├── Components/   Blazor UI: mail, compose, calendar, contacts, files, settings, admin
├── Controllers/  JSON endpoints for sign-in, setup and browser-side requests
├── Services/     IMAP, SMTP, ManageSieve, CalDAV/CardDAV and WebDAV clients, MIME, iCalendar, vCard, OpenPGP glue
├── Data/         EF Core entities and DbContext (SQLite or PostgreSQL)
└── wwwroot/js/pgp  OpenPGP implementation that runs in the browser
```

See [docs/design.md](docs/design.md) for the design notes. Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md), and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Simon Soanes.

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution and third-party components. Unless required by applicable law or agreed to in writing, the software is distributed on an "AS IS" basis, without warranties or conditions of any kind.
