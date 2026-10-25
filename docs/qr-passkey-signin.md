# Phone-assisted sign-in (QR) and passkey-wrapped IMAP credentials

Status: Part 1 (QR sign-in, with the password typed on the phone) is implemented. Part 2
(passkeys) is implemented for signing in on the same device; using a passkey on the phone page
of the QR flow, and the "approve from a signed-in phone" step-up, are not built yet.

## As built (Part 1)

- `QrCode` (in `Services/`): byte mode, level M QR encoder, rendered as inline SVG. It is
  tested against reference matrices from an independent encoder.
- `QrLoginService` holds pending requests and approved QR sessions in memory, and raises
  `Changed` and `SessionEnded`.
- `QrAuthController` (`api/auth/qr/*`) has start, redeem, describe, confirm, approve,
  sessions and sessions/revoke. Requests are rate-limited per IP (12 starts a minute, 60
  other calls a minute).
- The desktop UI is `QrSignIn` on the sign-in page. The phone UI is `/m/approve`.
- QR sessions are browser-session cookies with a fixed lifetime that is never extended
  (`QrLogin__SessionHours`, default 8, limited to 0.25–24). An open circuit is ended when
  the phone revokes the session or the time limit passes.
- A wrong match code cancels the request straight away. After 3 wrong passwords the request
  is cancelled too. Approve checks the phone token before it contacts IMAP.
- **How the phone revokes:** the phone isn't signed in. On approval it gets a revoke token
  and keeps it in `localStorage`. The token can only list and end the sessions that phone
  approved.
- **PGP:** a PGP passphrase is always typed on the device that decrypts. On a QR-signed-in
  desktop, the unlock dialog and the key forms show a warning. For a passphrase, the warning
  says it could be recorded. For a security key, it says decrypted content can still be seen.
- Not built yet:
  - an idle timeout (the lifetime is fixed)
  - approximate location on the phone (only IPs are shown)
  - the "approve from a phone that's already signed in" variant
  - a server-side list of QR sessions in Settings

## As built (Part 2, same-device passkeys)

- **Adding one:** Settings → Account → **Passkeys** → *Add a passkey*, while signed in with the
  password (so it's in memory to wrap). Not offered on a desktop a phone signed in by QR, because
  that browser would hold the key. The passkey is discoverable (`residentKey: 'required'`),
  user verification is required, `attestation: 'none'`, and ES256 or RS256 keys are accepted.
  If the authenticator doesn't return the PRF output at creation, the browser asks it once more
  with `get`. Without PRF the passkey isn't saved.
- **Signing in:** *Sign in with a passkey* on the sign-in page. PRF salts have to be given per
  credential up front, so the server needs to know whose passkey it is: the user types the email
  address, or the browser offers the credential ids it used before (`localStorage`,
  `nullify.passkeys`; ids aren't secret). An address without passkeys gets a made-up credential
  and salt that are stable per address, so the options don't reveal which addresses have them.
- **Server:** `WebAuthn` (CBOR/COSE with `System.Formats.Cbor`, ECDsa/RSA) checks client data
  (type, challenge, origin, not cross-origin), the RP id hash, the UP and UV flags, the
  signature, the user handle and the signature counter. `PasskeyCeremonies` holds challenges in
  memory for 3 minutes, single use. `PasskeyController` (`api/auth/passkey/*`) is rate-limited to
  60 requests a minute per IP.
- **Wrapping:** `Passkeys.WrappedCredential` = nonce | tag | AES-256-GCM(KEK, Data Protection
  (`Nullify.WebMail.Passkey.v1`) of login + password), with AAD `UserId|CredentialId|WrapVersion`.
  Each sign-in unwraps with the current salt's KEK and wraps again under a new salt's KEK.
  `WrapVersion` is a concurrency token, so if two sign-ins race with one passkey, only one of them
  wraps again.
- **Browser:** `wwwroot/js/passkey.js` imports nothing and doesn't touch the PGP code. PRF
  evaluates `SHA-256("nullify-webmail/imap-wrap/v1" ‖ salt)`. The KEK is
  `HKDF-SHA256(prf, salt = empty, info = "imap-kek/v1" ‖ credentialId)`. Keys go to the server
  by `fetch`, never through the Blazor circuit, and .NET only gets `{ ok, error }`.
  `tests/pgp/passkey.test.mjs` checks the PRF inputs and that no PRF output is sent.
- **Password changed:** IMAP rejects the unwrapped password, so the passkey is marked
  *Needs updating*. After a password sign-in, *Update* in Settings wraps the new password under
  that passkey (one more ceremony).
- **Removing** a passkey also ends the sessions it signed in (`nullify_passkey` claim).
  Passkey sessions are ordinary 7-day sessions, and passkey sign-ins don't trust the computer.
- **Upgrades:** the `Passkeys` table is created on existing SQLite *and* PostgreSQL databases
  at startup with `CREATE TABLE IF NOT EXISTS`.

## Goals

1. A user can sign in on a desktop they don't fully trust (shared PC, kiosk, a
   machine that might have a keylogger) **without typing their mail password on
   it, and without the password ever reaching it** in any form.
2. After the first time, the password isn't typed anywhere. A passkey stands in
   for it.
3. The IMAP password is exposed as little as possible: on the wire, at rest, and
   in memory.

What this doesn't do: a compromised desktop can still read the mail shown on it
and use its own session while that session lasts. The design limits that to one
short, revocable session and keeps the reusable secret (the password) off the
machine.

## Where things stand today

- `AuthService.LoginAsync` checks the username and password against IMAP. It
  then builds a `CredentialInfo`, password included, and signs in with a cookie.
- `MemoryTicketStore` keeps the ticket, which holds the credential, in server
  memory. The cookie carries only a session key. Restarting the server signs
  everyone out.
- Cookies last 7 days, are persistent, and use a sliding expiry.
- The browser already uses WebAuthn PRF (`pgp-bridge.js`) to unlock PGP keys.
  The rule there is absolute: **PGP passphrases and PRF output never reach the
  server.** This design has to keep that rule while sending a *different* PRF
  output to the server (see [Keeping the PGP rule](#keeping-the-pgp-rule)).

Two facts shape the rest of the design:

- IMAP `LOGIN`/`AUTHENTICATE PLAIN` needs the real password on the server every
  time it opens a connection. Passkeys can't authenticate to IMAP. The only real
  way round that is OAUTHBEARER/XOAUTH2 against an identity provider (Dovecot
  supports it), which is out of scope here.
- So the server has to hold the password while a session is live. What we *can*
  control is (a) which devices it passes through and (b) what is stored once no
  session is live.

## As built: "I trust this computer" (the opposite of QR sign-in)

On a computer the user owns, a checkbox on the password sign-in keeps the login so the
computer stays signed in through server restarts and session expiry.

- **The cookie:** `TrustedDeviceService` seals `{deviceId, login, password}` with a
  time-limited Data Protection protector (`Nullify.WebMail.TrustedDevice.v1`). It goes in
  the `nullify.webmail.device` cookie, which is HttpOnly, `SameSite=Lax`, persistent, and
  expires after 30 days by default (`TrustedDevice__Days`). Each restore starts the 30 days
  again.
- **The table:** a `TrustedDevices` row (user, device id, browser description, dates) holds
  no secret. The cookie is refused without its row, so Settings → Account → **Trusted
  computers** can revoke a computer. Revoking also ends that computer's open session.
- **Restoring:** a GET page request (`Accept: text/html`, not `/api`, `/_blazor` or
  `/_framework`) with no session but with the cookie signs in again. Servers are resolved
  again and the password is checked with IMAP:
  - If it's rejected (for example, it was changed), the computer stops being trusted.
  - If IMAP can't be reached, the sign-in goes ahead and the mail view reports the outage.
- **Signing out** of a trusted computer also stops trusting it. Otherwise it would sign
  straight back in.
- QR sign-ins are never trusted.
- **Exposure:** the cookie and the server's key ring (`keys/`) together reveal the password.
  This is the trade-off the user accepts for a computer they own. Neither one alone is
  enough.
- **Upgrades:** the `TrustedDevices` table is created on existing databases at startup with
  `CREATE TABLE IF NOT EXISTS`, because `EnsureCreated` only builds new databases.

---

## Part 1 — Signing in by QR code

### Flow

```mermaid
sequenceDiagram
    participant D as Desktop browser
    participant S as Server
    participant P as Phone browser
    D->>S: POST /api/auth/qr/start
    S-->>D: {id, code, expires} + Set-Cookie qr_bind (HttpOnly)
    Note over D: Shows the QR for https://host/m/approve#id<br/>and the match code "47"
    P->>S: Scan → GET /m/approve (id stays in the fragment)
    P->>S: POST /api/auth/qr/{id}/describe
    S-->>P: Desktop browser/OS, IP + rough location, time, 3 candidate codes
    Note over P: User picks "47" and enters username + password<br/>(or uses a passkey, see Part 2)
    P->>S: POST /api/auth/qr/{id}/approve {code, username, password}
    S->>S: IMAP verify; build ticket; state = Approved
    S-->>D: Circuit event "approved" (no polling)
    D->>S: POST /api/auth/qr/{id}/redeem (qr_bind cookie)
    S-->>D: Set-Cookie nullify.webmail.auth (session key only)
    S-->>P: "Desktop signed in", with a Sign it out button
```

The password goes **phone → server** only. The desktop only ever receives the
session cookie it already gets today. The cookie is an opaque key into
`MemoryTicketStore`.

### The pending-login record (in memory, like the ticket store)

```csharp
sealed class PendingQrLogin
{
    byte[] Id;               // 128-bit random; the only thing in the QR
    byte[] BindHash;         // SHA-256 of the desktop's qr_bind cookie value
    string MatchCode;        // 2 digits shown on the desktop
    DateTime ExpiresUtc;     // created + 120 s; the desktop rotates the QR every 60 s
    QrState State;           // Pending → Described → Approved → Redeemed | Failed
    int ApproveAttempts;     // max 3, then Failed
    string DesktopUa, DesktopIp;
    AuthenticationTicket? Ticket; // set on approve, removed on redeem
}
```

Store it in a `ConcurrentDictionary` with a sweeper, in the same style as
`MemoryTicketStore`. It never goes to the database.

### Why each piece is there

| Control | Stops |
|--|--|
| `qr_bind` HttpOnly cookie, checked on redeem | Someone who photographs or relays the QR approving it and then redeeming the session in **their own** browser. Only the browser that started the login can collect the session. |
| Id carried in the URL fragment (`#id`), posted by page JS | The id turning up in proxy or Caddy access logs and `Referer` headers. |
| **Number matching** (the phone picks the code the desktop shows from 3 options) | QRLjacking. An attacker shows a victim *the attacker's* QR on a phishing page, and the victim approves the attacker's desktop. The victim can't see the right code, so a blind approval fails. |
| Desktop details on the phone (browser, OS, IP, approximate location, time) | The same attack, through the user's own judgement ("that isn't my PC"). |
| 120 s expiry, single use, at most 3 approval attempts, rate limit per IP on `start` and `approve` | Brute-forcing ids and codes, and replaying them. |
| Redeem via `fetch` with a custom header plus `SameSite=Lax` | CSRF on redeem. It also fits the existing `nullifyAuth.postJson` pattern, because the cookie has to be set by a real browser request and not by the circuit. |
| Ticket handed over in memory, keyed by the id, deleted on redeem | The credential being serialised anywhere new. |

The desktop learns about the approval through its Blazor circuit (an in-process
event), so there's no polling endpoint. Then it calls
`nullifyAuth.postJson('/api/auth/qr/{id}/redeem')` and reloads.

### Session policy for desktops signed in by QR

These desktops are by definition the less trusted ones, so their sessions
should be different from a normal sign-in:

- **Not persistent** (a session cookie, gone when the browser closes), a 30-minute
  idle timeout, and an 8-hour absolute limit. Mark the ticket
  `amr=qr` so the cookie events can enforce this.
- **Revocable from the phone.** The approval page stays open with *Sign out
  desktop* and lists recent QR sessions. Revoking removes the ticket from
  `MemoryTicketStore`, the IMAP pool entry closes, and the circuit is torn down
  on its next request.
- The phone itself does **not** get signed in, unless the user ticks "also sign in
  on this phone".

### Variant: approving from a phone that's already signed in

If the phone already has a webmail session, the approve page skips the password.
It shows "Sign in the desktop as alice@example.com?" with number matching, and
the server **copies the credential from the phone's ticket** into a new desktop
ticket. No password is typed anywhere at that point.

A stolen phone cookie mustn't be enough to authorise new desktops. So this
variant requires a fresh **passkey assertion with user verification**
(`uv=true`) on the phone at approval time (Part 2). Without a passkey, it falls
back to asking for the password.

### Implementation notes

- QR rendering: the "only Microsoft packages / no third-party JS" constraint means
  writing a small QR encoder (byte mode, ECC level M, versions 1–10 are enough for
  a URL of about 60 characters). Render it to inline SVG on the server. That's
  roughly 400–500 lines plus test vectors.
- Endpoints, all on `AuthController` (`[AllowAnonymous]` except where noted):
  `qr/start`, `qr/{id}/describe`, `qr/{id}/approve`,
  `qr/{id}/approve-session` (`[Authorize]` + passkey), `qr/{id}/redeem`,
  `qr/sessions` and `qr/sessions/{key}/revoke` (`[Authorize]`).
- Separate the "verify against IMAP and build `CredentialInfo`" step in
  `LoginAsync` from `SignInAsync`, so the approve path can build a ticket for a
  *different* HttpContext than the one handling the request.
- Lower the default `ExpireTimeSpan` for QR tickets only. Normal sign-ins keep
  7 days.

---

## Part 2 — Passkeys that unlock the stored IMAP password

### Yes, this works, through the WebAuthn PRF extension

A passkey can't log in to IMAP. But with PRF it **can derive a secret key that
only that authenticator can reproduce**, and that key can encrypt the IMAP
password at rest. The passkey does two jobs at once:

1. **Authentication.** A normal WebAuthn assertion, checked by the server against
   the stored public key. This proves who the user is.
2. **Decryption.** The PRF output, after a KDF, unwraps the stored password. That
   recovers the password the server needs to talk to IMAP.

### What is stored (new `Passkey` table)

| Column | Notes |
|--|--|
| `Id`, `UserId`, `Name`, `CreatedUtc`, `LastUsedUtc` | |
| `CredentialId` (bytes), `PublicKey` (COSE), `SignCount`, `Transports` | Standard WebAuthn relying-party state. |
| `UserHandle` | 32 random bytes. It allows sign-in without a username (discoverable credential). |
| `PrfSalt` (32 bytes) | The salt the *current* wrap was made with. |
| `WrappedCredential` | `AES-256-GCM(KEK, nonce, DataProtect(login + password))`, AAD = `UserId ‖ CredentialId ‖ WrapVersion` |
| `WrapVersion` | A counter that goes up each time the wrap is rotated. |

The encryption has two layers, and both have to be broken:

- **PRF layer (the outer layer):** without the physical authenticator *and* the user
  verifying on it (biometric or PIN), the blob is useless. A database dump, a
  backup, or the `keys/` folder doesn't reveal it.
- **DataProtection layer (the inner layer):** a PRF output on its own (for example,
  captured from a compromised browser) plus the database is still not enough
  without the server's key ring.

The server keeps **no plaintext or server-only-decryptable copy** of the
password for passkey users once all sessions have ended. Between sessions, the
password exists only in a form that needs the user's authenticator.

### Sign-in with a passkey

```mermaid
sequenceDiagram
    participant B as Browser (phone, or a trusted desktop)
    participant S as Server
    B->>S: POST /api/auth/passkey/options
    S-->>B: challenge, rpId, PRF salts {first: salt_n, second: salt_n+1}
    Note over B: navigator.credentials.get (user verification required)<br/>input_i = SHA-256("nullify-webmail/imap-wrap/v1" ‖ salt_i)<br/>KEK_i = HKDF(prf_i, info="imap-kek/v1" ‖ credId)
    B->>S: POST /api/auth/passkey/verify {assertion, KEK_n, KEK_n+1}
    S->>S: 1. Verify the assertion (challenge, origin, rpId, UV flag, signCount)
    S->>S: 2. Unwrap with KEK_n → password
    S->>S: 3. IMAP verify
    S->>S: 4. Re-wrap with KEK_n+1; store salt_n+1; discard both KEKs
    S-->>B: Session cookie (or approve the QR desktop)
```

Key points:

- **Check the assertion before using the KEK.** A KEK without a valid,
  fresh assertion is never tried.
- **The salt changes on every use.** PRF accepts two inputs per ceremony. The
  server unwraps with the current salt and re-wraps with the next one. A KEK that
  a compromised browser captures stops working after the next sign-in. That
  narrows a "steal the KEK now, dump the database later" attack to the gap
  between two sign-ins.
- **Changing the IMAP password:** the unwrap succeeds, but IMAP rejects the old
  password. The user then types the new password once (on the phone), and it's
  re-wrapped under the passkey just used. The user's *other* passkeys can't be
  re-wrapped, because the server doesn't have their PRF outputs. They're marked
  stale and fall back to asking for the password the next time they're used.
- Enrolment happens straight after a successful password sign-in, while the
  password is in memory: *"Sign in with a passkey next time?"* →
  `navigator.credentials.create` with `residentKey: 'required'`,
  `userVerification: 'required'`, and PRF evaluated at creation where the
  authenticator supports it. If it doesn't, an immediate `get` follows, the same
  way `registerSecurityKey` does it.
- Server-side WebAuthn verification can be done with Microsoft packages only:
  `System.Formats.Cbor` for authenticator data and COSE keys, plus
  `ECDsa`/`RSA`/`Ed25519` from `System.Security.Cryptography`. Request
  `attestation: 'none'`, so no attestation-chain parsing is needed. .NET 10's
  Identity passkey support is another option, but it would mean adopting
  ASP.NET Identity, which this app deliberately doesn't use.

### Keeping the PGP rule

This is the subtle part. A KEK derived from PRF output is now sent to the
server, so we have to guarantee the server can never get the client to produce
**the PGP PRF output**:

1. **The client separates the inputs.** The browser never passes a
   server-supplied salt to PRF as it is. It always evaluates
   `SHA-256("nullify-webmail/imap-wrap/v1" ‖ serverSalt)`. The PGP unlock uses
   its own raw client-generated salt. A malicious or compromised server would
   need a SHA-256 preimage to make the login ceremony evaluate the PGP salt.
2. **Only a derived key leaves the browser.** That's HKDF of the PRF output,
   with an IMAP-specific `info`. The raw PRF output is never sent.
3. **Separate credentials.** The login passkey is a discoverable credential with
   its own `UserHandle`. PGP security keys stay non-discoverable credentials
   registered by `pgp-bridge.js`. Code paths (and files) stay separate:
   `passkey-login.js` must not import the PGP module's PRF helpers.
4. Add a test: the bytes passed to `prf.eval` by the login module never equal the
   salt given to it.

### Where should the passkey live?

| Option | What the desktop sees | Verdict |
|--|--|--|
| **Passkey on the phone, used through the Part 1 QR flow** (the phone page runs the passkey ceremony itself) | Only the session cookie | **Recommended for untrusted desktops.** The KEK exists only on the phone and the server. |
| Passkey on the phone, used through WebAuthn *hybrid* (the browser's own "use a phone" QR on the desktop) | The assertion **and the KEK**, because the PRF result comes back to the desktop's JavaScript | Better proximity and phishing resistance (BLE), but the desktop holds a KEK. Rotating salts limits the harm. Fine for your own desktop, not for an untrusted one. |
| Platform passkey on the desktop (Windows Hello, Touch ID) | The KEK | Only for the user's own trusted machine. Easiest to use day to day. |

PRF support differs between platforms and browsers: iCloud Keychain/iOS 18+,
Google Password Manager on Android, YubiKey 5 and current Chromium all support
it. Some platform authenticators and older browsers don't. If PRF is missing,
the passkey is still accepted for **authentication**, but the user is told it
can't stand in for the password. On that device they keep using the
password-on-phone QR path.

### Optional: re-signing in after a restart

Tickets live in memory, so restarting the server or the container signs
everyone out. With a passkey that's one tap. Without one, it means retyping the
password. This keeps us from ever adding a persistent store of tickets that
contain passwords.

---

## The combined result

| Scenario | Where the password is typed | Where the plaintext password exists |
|--|--|--|
| Today | Desktop | Desktop (the form), the server's memory while a session is live |
| QR, password on the phone | Phone | Phone (the form), the server's memory while a session is live |
| QR + passkey on the phone | Nowhere (only once, at enrolment) | The server's memory while a session is live |
| Approving from a signed-in phone + passkey step-up | Nowhere | The server's memory while a session is live |

At rest, the password is only ever stored wrapped under a passkey PRF key. Once
no session is live, the server can't recover it alone.

Remaining exposure that only a protocol change would remove: the server must
hold the plaintext while a session is live. To remove that too, the mail server
would need OAUTHBEARER (webmail would then hold a token, not a password), or
per-application passwords that the user can revoke on their own.

## Threats and residual risk

| Threat | Result |
|--|--|
| Keylogger or compromised browser on the desktop | Password safe. The attacker can use and read that one session until it times out or the phone revokes it. |
| Someone photographs the QR | Can't redeem it without `qr_bind`. Blind approval fails number matching. |
| A phishing site shows the attacker's QR | The user can't see the right code. The phone shows the attacker's IP and location. Approval to the real origin is still possible if the user is socially engineered into it, which is the remaining risk shared by every QR-login scheme. |
| Database + key ring stolen | Passkey-wrapped passwords can't be recovered without the authenticators. |
| Malicious server tries to obtain the PGP PRF output | Blocked by the client separating PRF inputs ([Keeping the PGP rule](#keeping-the-pgp-rule)). |
| Stolen phone with a live webmail cookie | Can't approve new desktops without passkey user verification. |
| Server memory compromised while it runs | Passwords of live sessions are exposed. This is inherent to IMAP password authentication. |

## Phasing

1. Split `LoginAsync` into verify/build and sign-in. Add the QR encoder with tests.
2. QR flow with the password typed on the phone: endpoints, pending store,
   number matching, short-lived revocable desktop tickets, phone-side session
   list.
3. WebAuthn relying-party verification (CBOR/COSE) and the `Passkey` table.
   Passkey enrolment after a password sign-in, and passkey sign-in on the
   same device.
4. PRF-wrapped credentials with salt rotation. Use the passkey on the phone page
   of the QR flow. Step-up for "approve from a signed-in phone".
5. Account settings: list, rename and remove passkeys, view and revoke QR
   sessions, and show stale-wrap warnings.
