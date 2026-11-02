const CACHE = 'pandora-v7';
const ASSETS = ['./', './index.html', './app.js', './manifest.json'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  // Only cache-handle GETs from our own origin. Cross-origin /vault requests
  // pass straight through to the network.
  if (e.request.method !== 'GET' || !e.request.url.startsWith(self.location.origin)) return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});