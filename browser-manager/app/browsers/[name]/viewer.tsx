"use client";

import { useEffect, useState } from "react";
import Desktop from "./desktop";
import PageDesktop from "./page-desktop";

export default function Viewer({ name }: { name: string }) {
  const [transport, setTransport] = useState<"page" | "vnc" | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    let disposed = false;
    setError("");
    setTransport(null);
    void fetch("/api/config", { cache: "no-store", signal: controller.signal }).then(async response => {
      if (!response.ok || response.redirected) throw new Error("Could not load this viewer. Reload to renew your sign-in.");
      const config = await response.json();
      if (!["page", "vnc"].includes(config.transport)) throw new Error("This server reported an unsupported viewer transport.");
      if (!disposed) setTransport(config.transport);
    }).catch(error => {
      if (!disposed) setError(error?.name === "AbortError" ? "The viewer configuration timed out. Retry or reload to sign in again." : error.message);
    }).finally(() => clearTimeout(timeout));
    return () => { disposed = true; clearTimeout(timeout); controller.abort(); };
  }, [name, attempt]);
  if (transport === "vnc") return <Desktop name={name} />;
  if (transport === "page") return <PageDesktop name={name} />;
  return <main className="desktop-workspace"><section className="connection-overlay"><div className="connection-card">
    {!error && <span className="spinner" />}
    <h1>{error ? "Viewer unavailable" : "Opening your browser"}</h1>
    <p role="status">{error || "Checking this host’s authenticated viewer configuration…"}</p>
    {error && <div className="connection-actions"><button className="button primary" onClick={() => setAttempt(value => value + 1)}>Retry</button>
      <button className="button" onClick={() => window.location.reload()}>Reload / sign in</button><a className="button" href="/">All browsers</a></div>}
  </div></section></main>;
}
