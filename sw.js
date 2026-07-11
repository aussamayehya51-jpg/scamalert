// ScamAlert service worker — makes the phone guard work offline.
// The whole point of Layer 1 is that it protects you even with no internet,
// so we cache the app shell (index.html + the offline engine) on install.
// The AI endpoint (/api/) is NEVER cached — a "second opinion" must be live.
//
// ⚠️ RELEASE RITUAL: bump the number in CACHE on EVERY release.
// Changing this file is what tells every installed phone to fetch the new
// app + engine. Ship a smarter engine without bumping it and phones keep
// running the old rules from their cache.
// Paths are RELATIVE on purpose. The app is served both from a domain root
// (a real server) and from a subfolder (GitHub Pages: /scamalert/). Absolute
// "/index.html" paths would silently point at the wrong place on Pages.
const CACHE = 'scamalert-v10';
const ASSETS = [
  './', './index.html', './scamEngine.js', './manifest.webmanifest',
  './icon-192.png', './icon-512.png', './apple-touch-icon.png',
  './learn.html', './linkshield.html', './shield.html', './help.html'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // Live-only: never serve the AI or any API from cache. (The AI call is a POST,
  // so the method check alone would skip it — this is belt and braces.)
  if (url.pathname.indexOf('/api/') !== -1) return;
  if (e.request.method !== 'GET') return;

  // App shell: serve from cache first (instant + offline), update in background.
  e.respondWith(
    caches.match(e.request).then((hit) => {
      const net = fetch(e.request).then((resp) => {
        if (resp && resp.status === 200 && url.origin === location.origin) {
          const clone = resp.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => hit || caches.match('./index.html'));
      return hit || net;
    })
  );
});
