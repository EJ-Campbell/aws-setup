export type BrowserInstance = {
  name: string;
  url: string;
  state: "starting" | "running" | "stopped" | "error";
  createdAt: string;
  error?: string;
};

// HTTP: GET /api/browsers -> { browsers: BrowserInstance[] }
// POST /api/browsers -> { name, url? } -> BrowserInstance
// POST /api/browsers/:name/start -> {} -> BrowserInstance
// POST /api/browsers/:name/stop -> {} -> BrowserInstance
// GET /api/config -> { baseUrl: string }
// WS /browsers/:name/vnc -> binary RFB, authenticated on every upgrade.
// Desktop page /browsers/:name; names match /^[a-z0-9][a-z0-9-]{0,47}$/.
// All errors: { error: string }; no secrets/profile paths in public responses.
