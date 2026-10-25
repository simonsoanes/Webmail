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
