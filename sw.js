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
//
// ⚠️ AND: Cache Storage is per-ORIGIN, not per-app. On GitHub Pages this app
// shares aussamayehya51-jpg.github.io with Coffee Money, Aroma Caffeh and
// Credit Guardian. This file used to delete EVERY cache on that address that
// was not its own, which wiped a working shop's offline copy — and theirs did
// the same to ScamAlert. So everything below is scoped by name: we only ever
// read from, and only ever delete, caches beginning with our own prefix.
const PREFIX = 'scamalert-';
const CACHE = PREFIX + 'v12';
const HOME = './index.html';
const ASSETS = [
  './', HOME, './scamEngine.js', './manifest.webmanifest',
  './icon-192.png', './icon-512.png', './apple-touch-icon.png',
  './learn.html', './linkshield.html', './shield.html', './help.html'
];

// Our caches only — the new one first, then any older one we still have. That
// fallback matters here more than anywhere: a phone that updates on one bar of
// signal must not be left with no offline guard at all.
async function mine(req, alt) {
  const keys = (await caches.keys()).filter((k) => k.startsWith(PREFIX));
  keys.sort((a, b) => (a === CACHE ? -1 : b === CACHE ? 1 : 0));
  for (const k of keys) {
    const c = await caches.open(k);
    const hit = (await c.match(req)) || (alt ? await c.match(alt) : undefined);
    if (hit) return hit;
  }
  return undefined;
}

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

// Retire OUR old versions only — never another app's — and only once the new
// cache really holds the app shell.
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.match(HOME))
      .then((ready) => (ready ? caches.keys() : []))
      .then((keys) => Promise.all(
        keys.filter((k) => k.startsWith(PREFIX) && k !== CACHE).map((k) => caches.delete(k))
      ))
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
    mine(e.request).then((hit) => {
      const net = fetch(e.request).then((resp) => {
        if (resp && resp.status === 200 && url.origin === location.origin) {
          const clone = resp.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => hit || mine(HOME));
      return hit || net;
    })
  );
});
