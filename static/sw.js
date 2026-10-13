/**
 * PhishGuard V2 Service Worker
 * Provides offline caching for static assets (styles, scripts, fonts)
 * and passes API requests dynamically to the backend.
 */
const CACHE_NAME = "phishguard-v2-cache-v1";
const STATIC_ASSETS = [
  "/",
  "/dashboard",
  "/about",
  "/static/css/style.css",
  "/static/js/main.js",
  "/static/js/dashboard.js",
  "/manifest.json"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn("Pre-caching non-critical failure:", err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  // Do not intercept API or form POST requests
  if (event.request.method !== "GET" || event.request.url.includes("/api/")) {
    return;
  }

  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request);
    })
  );
});
