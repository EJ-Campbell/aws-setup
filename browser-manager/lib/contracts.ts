export type BrowserInstance = {
  name: string;
  label: string;
  url: string;
  state: "starting" | "running" | "stopped" | "error";
  viewport: { mode: "desktop" | "phone"; width: number; height: number };
  createdAt: string;
  error?: string;
};

// HTTP: GET /api/browsers -> { browsers: BrowserInstance[] }
// POST /api/browsers -> { name, url? } -> BrowserInstance
// POST /api/browsers/:name/start -> {} -> BrowserInstance
// POST /api/browsers/:name/stop -> {} -> BrowserInstance
// POST /api/browsers/:name/rename -> { label } -> { browser: BrowserInstance }
// POST /api/browsers/:name/viewport -> { mode: "desktop" } or { mode: "phone", width, height }
// -> { browser: BrowserInstance }. Phone bounds: width 320–500, height 480–900 (integer CSS pixels).
// Explicit resize affects this browser's shared desktop, not other browsers. No browser restart.
// Live viewport survives viewer reconnects; restarting the browser resets to Desktop (1440×900).
// Labels are display-only, trimmed 1–80 characters without control characters. Names/URLs stay fixed.
// GET /api/config -> { baseUrl: string }
// WS /browsers/:name/vnc -> binary RFB, authenticated on every upgrade.
// Desktop page /browsers/:name; names match /^[a-z0-9][a-z0-9-]{0,47}$/.
// All errors: { error: string }; no secrets/profile paths in public responses.
