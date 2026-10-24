// Browser-side auth helper. Login/setup/logout MUST run as real browser HTTP
// requests so the auth cookie lands in the browser jar — a server-side
// HttpClient inside the Blazor circuit can never set a cookie the browser sees.
window.nullifyAuth = {
    postJson: async (url, body) => {
        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                credentials: 'same-origin'
            });
            const text = await resp.text();
            return { ok: resp.ok, status: resp.status, text: text };
        } catch (e) {
            return { ok: false, status: 0, text: String(e) };
        }
    },

    timeZone: () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return null; } },

    // Sign-in request id from a scanned QR code. It travels in the fragment so it stays out of server logs.
    qrId: () => location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : null,

    // Scanning another code into an open approval page only changes the fragment; start over with it.
    reloadOnHashChange: () => window.addEventListener('hashchange', () => location.reload(), { once: true }),

    // Revoke tokens for desktops this phone signed in. They can only end those sessions, nothing more.
    qrTokens: {
        list: () => {
            try {
                const v = JSON.parse(localStorage.getItem('nullify.qrSessions') || '[]');
                return Array.isArray(v) ? v.filter(t => typeof t === 'string') : [];
            } catch (e) { return []; }
        },
        save: (tokens) => {
            try { localStorage.setItem('nullify.qrSessions', JSON.stringify(tokens.slice(-20))); } catch (e) { }
        },
        add: (token) => {
            const q = window.nullifyAuth.qrTokens;
            q.save([...q.list().filter(t => t !== token), token]);
        }
    }
};
