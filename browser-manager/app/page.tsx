"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { BrowserInstance } from "../lib/contracts";
import { Icon } from "./ui";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  if (response.status === 401 || response.status === 403) {
    throw new Error("Access expired or was denied. Reload this page to sign in again.");
  }
  const data = await response.json().catch(() => null);
  if (!response.ok || data === null) {
    throw new Error(data?.error ?? "The server could not complete this request.");
  }
  return data as T;
}

export default function Dashboard() {
  const [browsers, setBrowsers] = useState<BrowserInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pending, setPending] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const mutation = useRef(false);
  const formName = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      const result = await request<{ browsers: BrowserInstance[] }>("/api/browsers");
      setBrowsers(result.browsers);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to refresh browser status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await refresh();
      if (!disposed) timer = setTimeout(poll, 5000);
    };
    void poll();
    return () => { disposed = true; clearTimeout(timer); };
  }, [refresh]);

  async function mutate(path: string, key: string, body: object) {
    if (mutation.current) return false;
    mutation.current = true;
    setPending(key);
    setNotice("");
    try {
      const result = await request<BrowserInstance>(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      setBrowsers((current) => [...current.filter((item) => item.name !== result.name), result]
        .sort((a, b) => a.name.localeCompare(b.name)));
      setNotice(key === "create" ? `${result.name} created.` : `${result.name} is ${result.state}.`);
      return true;
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : "Request interrupted. Refresh status before trying again.");
      return false;
    } finally {
      mutation.current = false;
      setPending("");
    }
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    if (await mutate("/api/browsers", "create", { name, ...(url ? { url } : {}) })) {
      setName("");
      setUrl("");
    }
  }

  const running = browsers.filter((item) => item.state === "running").length;
  return (
    <main className="dashboard">
      <header className="dashboard-header">
        <a className="brand" href="/"><span className="brand-mark"><Icon name="browser" /></span> Browser manager</a>
        <span className="private-label"><Icon name="lock" size={14} /> Private workspace</span>
      </header>

      <section className="intro">
        <span className="eyebrow">YOUR REMOTE WORKSPACE</span>
        <h1>A browser for<br className="phone-break" /> every task.</h1>
        <p>Separate desktops. Separate profiles. Open any of them from your computer or phone.</p>
      </section>

      <section className="create-panel" aria-labelledby="create-heading">
        <div className="section-intro"><h2 id="create-heading">Create a browser</h2><p>Give it a name. Your profile stays here when you stop.</p></div>
        <form onSubmit={create} className="create-form">
          <label>Browser name<input ref={formName} name="name" value={name} onChange={(event) => setName(event.target.value)} placeholder="research" pattern={"[a-z0-9][a-z0-9\\-]{0,47}"} maxLength={48} required autoCapitalize="none" autoCorrect="off" spellCheck={false} aria-describedby="name-hint" /></label>
          <label>Start page <span className="optional">optional</span><input name="url" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" autoCapitalize="none" autoCorrect="off" spellCheck={false} /></label>
          <button className="button primary create-submit" disabled={!!pending || !name}><Icon name="plus" size={18} /> {pending === "create" ? "Creating…" : "Create browser"}</button>
          <p id="name-hint" className="field-hint">Lowercase letters, numbers, and hyphens. Up to 48 characters.</p>
        </form>
      </section>

      {notice && <div className="notice" role="status">{notice}<button className="icon-button" onClick={() => setNotice("")} aria-label="Dismiss notice"><Icon name="close" size={16} /></button></div>}
      {error && <div className="notice error" role="alert"><div>{error}<small>Displayed browser states may be out of date.</small></div><button className="button" onClick={() => void refresh()}>Refresh</button></div>}

      <section aria-labelledby="browsers-heading" className="browser-section">
        <div className="section-heading"><div><h2 id="browsers-heading">Your browsers <span className="count">{browsers.length}</span></h2><p>{loading ? "Loading your workspace…" : `${running} running · ${browsers.length} total`}</p></div><button className="button quiet" onClick={() => void refresh()} aria-label="Refresh browsers"><Icon name="refresh" size={17} /><span>Refresh</span></button></div>
        {!loading && !error && browsers.length === 0 ? (
          <div className="empty-state"><span className="empty-icon"><Icon name="browser" size={30} /></span><h3>Your workspace starts here</h3><p>Create your first browser above. Each one has its own cookies, logins, and browsing history.</p><button className="button" onClick={() => formName.current?.focus()}>Name your first browser</button></div>
        ) : (
          <ul className="browser-grid" aria-label="Browser desktops" aria-busy={loading}>
            {browsers.map((browser) => (
              <li className="browser-card" key={browser.name}>
                <div className="card-top"><span className="browser-icon"><Icon name="browser" size={23} /></span><span className="state" data-state={browser.state}><span />{browser.state}</span></div>
                <h3>{browser.name}</h3><p className="browser-url" title={browser.url}>{browser.url || "Blank start page"}</p>
                {browser.error && <p className="card-error">{browser.error}</p>}
                <div className="card-actions">
                  {browser.state === "running" ? <a className="button primary" href={`/browsers/${encodeURIComponent(browser.name)}`}>Open desktop<Icon name="arrow" size={17} /></a> : <button className="button primary" disabled={!!pending || browser.state === "starting"} onClick={() => void mutate(`/api/browsers/${encodeURIComponent(browser.name)}/start`, `start:${browser.name}`, {})}>{browser.state === "starting" || pending === `start:${browser.name}` ? "Starting…" : "Start browser"}</button>}
                  <button className="button quiet" disabled={!!pending || browser.state === "stopped"} onClick={() => void mutate(`/api/browsers/${encodeURIComponent(browser.name)}/stop`, `stop:${browser.name}`, {})}>{pending === `stop:${browser.name}` ? "Stopping…" : "Stop"}</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
      <footer className="dashboard-footer"><Icon name="lock" size={14} /> Access is private. Stopping a browser keeps its saved profile.</footer>
    </main>
  );
}
