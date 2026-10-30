// Service worker for the installed app. It caches nothing but the offline page: mail,
// keys and session data only ever come from the server, never from a cache on disk.
const CACHE = 'nullify-offline-v1';
const OFFLINE = new URL('offline.html', self.registration.scope).href;

self.addEventListener('install', event => {
    event.waitUntil(caches.open(CACHE).then(c => c.add(new Request(OFFLINE, { cache: 'reload' }))));
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil((async () => {
        for (const key of await caches.keys())
            if (key !== CACHE) await caches.delete(key);
        await self.clients.claim();
    })());
});

// Page loads go to the network; only when that fails is the offline page shown.
// Everything else is left to the browser.
self.addEventListener('fetch', event => {
    if (event.request.mode !== 'navigate') return;
    event.respondWith(fetch(event.request).catch(async () =>
        (await caches.match(OFFLINE)) ?? Response.error()));
});

// A notification clicked: bring the app forward and tell it what to open.
self.addEventListener('notificationclick', event => {
    event.notification.close();
    const data = event.notification.data || {};
    event.waitUntil((async () => {
        const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        const app = windows.find(c => c.url.startsWith(self.registration.scope));
        if (app) {
            await app.focus();
            app.postMessage({ type: 'notification-click', kind: data.kind, id: data.id });
        } else {
            await self.clients.openWindow(self.registration.scope);
        }
    })());
});
