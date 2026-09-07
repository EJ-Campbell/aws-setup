"use client";

import { useEffect, useRef, useState } from "react";
import type RFB from "@novnc/novnc";
import type { BrowserInstance } from "../../../lib/contracts";
import { Icon } from "../../ui";
import { createReconnectLoop } from "../../../lib/reconnect.mjs";

type Connection = "connecting" | "connected" | "disconnected" | "error";
const keys = { enter: 0xff0d, tab: 0xff09, escape: 0xff1b, backspace: 0xff08, control: 0xffe3, alt: 0xffe9, left: 0xff51 };

export default function Desktop({ name }: { name: string }) {
  const screen = useRef<HTMLDivElement>(null);
  const workspace = useRef<HTMLElement>(null);
  const client = useRef<RFB | null>(null);
  const reconnect = useRef<() => void>(() => {});
  const textInput = useRef<HTMLTextAreaElement>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [detail, setDetail] = useState("");
  const [retryDelay, setRetryDelay] = useState<number | null>(null);
  const [foreground, setForeground] = useState(true);
  const [fit, setFit] = useState(true);
  const [keyboard, setKeyboard] = useState(false);
  const [text, setText] = useState("");
  const [feedback, setFeedback] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
  const [canFullscreen, setCanFullscreen] = useState(false);
  const [label, setLabel] = useState(name);
  const connected = connection === "connected";

  useEffect(() => {
    const abort = new AbortController();
    setLabel(name);
    void fetch("/api/browsers", { cache: "no-store", signal: abort.signal })
      .then(async (response) => {
        if (!response.ok) return;
        const data: { browsers: BrowserInstance[] } = await response.json();
        const browser = data.browsers.find((entry) => entry.name === name);
        if (!abort.signal.aborted && browser) setLabel(browser.label ?? name);
      }).catch(() => {});
    return () => abort.abort();
  }, [name]);

  useEffect(() => {
    let disposed = false;
    let rfb: RFB | undefined;
    let generation = 0;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const isActive = () => document.visibilityState === "visible" && document.hasFocus();
    const loop = createReconnectLoop(connect, setRetryDelay, isActive());
    reconnect.current = loop.retry;

    function connect() {
      if (!isActive()) { loop.setActive(false); setForeground(false); return; }
      const attempt = ++generation;
      clearTimeout(timeout);
      rfb?.disconnect();
      rfb = undefined;
      client.current = null;
      setConnection("connecting");
      setDetail("");
      const current = () => !disposed && generation === attempt;
      const failed = (message: string, error = false) => {
        if (!current()) return;
        clearTimeout(timeout);
        setConnection((state) => error || state === "error" ? "error" : "disconnected");
        setDetail((detail) => detail || message);
        loop.disconnected();
      };
      // A half-open socket or stalled handshake must not leave a phone connecting forever.
      timeout = setTimeout(() => {
        if (!current()) return;
        failed("The connection timed out. Check that the desktop is running, or reload to renew your sign-in.");
        generation++;
        rfb?.disconnect();
      }, 10_000);
      void import("@novnc/novnc").then(({ default: RFBClient }) => {
        if (!current() || !screen.current || !isActive()) return;
        const url = new URL(`/browsers/${encodeURIComponent(name)}/vnc`, window.location.href);
        url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const next = new RFBClient(screen.current, url.href, { shared: true });
        rfb = next;
        next.scaleViewport = true;
        // Scaling is local: one viewer must not resize another viewer's desktop.
        next.resizeSession = false;
        next.background = "#171d25";
        next.focusOnClick = true;
        client.current = next;
        next.addEventListener("connect", () => {
          if (!current()) return;
          clearTimeout(timeout);
          loop.connected();
          setConnection("connected");
          setDetail("");
        });
        next.addEventListener("disconnect", (event) => {
          const clean = (event as CustomEvent<{ clean: boolean }>).detail.clean;
          failed(clean
            ? "The desktop connection closed. Your browser may still be running."
            : "Could not reach this desktop. Check that it is running, or reload to renew your sign-in.");
        });
        const authenticationFailure = () => {
          if (!current()) return;
          failed("The desktop rejected the connection. Reload to renew your sign-in, or check the desktop status.", true);
          generation++;
          next.disconnect();
        };
        next.addEventListener("credentialsrequired", authenticationFailure);
        next.addEventListener("securityfailure", authenticationFailure);
      }).catch(() => failed("The desktop viewer could not load. Reload this page to try again.", true));
    }

    const activityChanged = () => {
      const active = isActive();
      setForeground(active);
      loop.setActive(active);
    };
    const suspended = () => { setForeground(false); loop.setActive(false); };
    document.addEventListener("visibilitychange", activityChanged);
    window.addEventListener("focus", activityChanged);
    window.addEventListener("blur", activityChanged);
    window.addEventListener("pageshow", activityChanged);
    window.addEventListener("pagehide", suspended);
    setForeground(isActive());
    loop.retry();
    return () => {
      disposed = true;
      generation++;
      clearTimeout(timeout);
      loop.dispose();
      reconnect.current = () => {};
      document.removeEventListener("visibilitychange", activityChanged);
      window.removeEventListener("focus", activityChanged);
      window.removeEventListener("blur", activityChanged);
      window.removeEventListener("pageshow", activityChanged);
      window.removeEventListener("pagehide", suspended);
      client.current = null;
      rfb?.disconnect();
    };
  }, [name]);

  useEffect(() => { if (client.current) client.current.scaleViewport = fit; }, [fit, connection]);
  useEffect(() => {
    setCanFullscreen(Boolean(document.fullscreenEnabled && workspace.current?.requestFullscreen));
    const changed = () => setFullscreen(document.fullscreenElement === workspace.current);
    document.addEventListener("fullscreenchange", changed);
    return () => document.removeEventListener("fullscreenchange", changed);
  }, []);
  useEffect(() => {
    if (keyboard) { client.current?.blur(); textInput.current?.focus(); }
  }, [keyboard, connection]);

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await workspace.current?.requestFullscreen();
    } catch { setFeedback("Fullscreen is unavailable here. Fit to screen still works."); }
  }

  function sendKey(key: number, code: string) {
    if (!connected) return;
    client.current?.sendKey(key, code);
    setFeedback("Key sent to the remote desktop.");
  }

  function shortcut(letter: "l" | "v") {
    const rfb = client.current;
    if (!connected || !rfb) return;
    rfb.sendKey(keys.control, "ControlLeft", true);
    try { rfb.sendKey(letter.charCodeAt(0), `Key${letter.toUpperCase()}`); }
    finally { rfb.sendKey(keys.control, "ControlLeft", false); }
  }

  function browserBack() {
    const rfb = client.current;
    if (!connected || !rfb) return;
    rfb.sendKey(keys.alt, "AltLeft", true);
    try { rfb.sendKey(keys.left, "ArrowLeft"); }
    finally { rfb.sendKey(keys.alt, "AltLeft", false); }
    setFeedback("Back sent to the remote browser.");
  }

  function sendText(paste: boolean) {
    const rfb = client.current;
    if (!connected || !rfb || !text) return;
    if (paste) {
      rfb.clipboardPasteFrom(text);
      shortcut("v");
    } else {
      for (const character of text.replace(/\r\n?/g, "\n")) {
        if (character === "\n") rfb.sendKey(keys.enter, "Enter");
        else if (character === "\t") rfb.sendKey(keys.tab, "Tab");
        else {
          // RFB uses Latin-1 keysyms directly and X11's Unicode keysym range beyond it.
          const point = character.codePointAt(0)!;
          rfb.sendKey(point >= 0x20 && point <= 0xff ? point : 0x01000000 | point, null);
        }
      }
    }
    setText("");
    setFeedback(paste ? "Paste sent to the selected remote field." : "Text sent to the selected remote field.");
    textInput.current?.focus();
  }

  return (
    <main className="desktop-workspace" ref={workspace}>
      <header className="desktop-header">
        <a href="/" className="icon-button back-button" aria-label="Back to your browsers"><Icon name="back" /></a>
        <div className="desktop-title"><h1>{label}</h1><span className="connection-status" data-state={connection} role="status"><span />{connected ? "Connected" : connection === "connecting" ? "Connecting…" : "Disconnected"}</span></div>
        <button className="button remote-back" disabled={!connected} onClick={browserBack} aria-label="Back in remote browser" title="Back in remote browser"><Icon name="browserBack" size={20} /><span>Back</span></button>
        <div className="desktop-toolbar" aria-label="Desktop controls">
          <button className="button quiet" aria-pressed={fit} onClick={() => setFit(!fit)} title={fit ? "Show desktop at actual size" : "Fit desktop to screen"}><Icon name="fit" size={18} /><span>Fit to screen</span></button>
          <button className="button quiet" aria-pressed={keyboard} aria-controls="keyboard-panel" onClick={() => setKeyboard(!keyboard)}><Icon name="keyboard" size={18} /><span>Keyboard</span></button>
          <button className="button quiet" disabled={!canFullscreen} onClick={() => void toggleFullscreen()} title={canFullscreen ? "Toggle fullscreen" : "Fullscreen is not supported in this browser"} aria-label={fullscreen ? "Exit fullscreen" : "Enter fullscreen"}><Icon name="expand" size={18} /><span className="fullscreen-label">{fullscreen ? "Exit fullscreen" : "Fullscreen"}</span></button>
          <button className="button quiet" onClick={() => reconnect.current()} disabled={connection === "connecting"} aria-label="Reconnect desktop"><Icon name="refresh" size={18} /><span>Reconnect</span></button>
        </div>
      </header>

      <section className="desktop-display" aria-label={`${label} remote desktop`}>
        <div ref={screen} className="vnc-screen" />
        {!connected && <div className={`connection-overlay${keyboard ? " compact" : ""}`}><div className="connection-card">
          {connection === "connecting" ? <span className="spinner" aria-hidden="true" /> : <Icon name="browser" size={32} />}
          <h2>{connection === "connecting" ? "Connecting to your desktop" : "Desktop disconnected"}</h2>
          <p>{detail || "Opening a private connection to your browser."}</p>
          <p role="status">{!foreground ? "Automatic reconnect is paused until you return to this tab." : retryDelay !== null ? `Retrying automatically in ${retryDelay} ${retryDelay === 1 ? "second" : "seconds"}…` : ""}</p>
          {connection !== "connecting" && <div className="connection-actions"><button className="button primary" onClick={() => reconnect.current()}>Reconnect</button><a className="button" href="/">Your browsers</a></div>}
        </div></div>}
      </section>

      {keyboard && <section className="keyboard-panel" id="keyboard-panel" aria-labelledby="keyboard-heading">
        <div className="keyboard-heading"><div><h2 id="keyboard-heading">Send to desktop</h2><p>Select a field in the desktop first. Text is sent only when you choose an action.</p></div><button className="icon-button" onClick={() => setKeyboard(false)} aria-label="Close keyboard controls"><Icon name="close" size={18} /></button></div>
        <div className="keyboard-input-row"><label className="sr-only" htmlFor="remote-text">Text for the remote desktop</label><textarea id="remote-text" ref={textInput} value={text} onChange={(event) => setText(event.target.value)} onFocus={() => client.current?.blur()} placeholder="Type or paste text here…" autoCapitalize="none" autoCorrect="off" spellCheck={false} rows={2} maxLength={4096} /><div className="text-actions"><button className="button primary" disabled={!connected || !text} onClick={() => sendText(false)}>Type text</button><button className="button" disabled={!connected || !text} onClick={() => sendText(true)}>Paste text</button></div></div>
        <div className="keyboard-bottom"><div className="special-keys" aria-label="Remote keyboard shortcuts"><button className="button key" disabled={!connected} onClick={() => { shortcut("l"); setFeedback("Address bar selected in the remote browser."); }}>Address bar</button><button className="button key" disabled={!connected} onClick={() => sendKey(keys.tab, "Tab")}>Tab</button><button className="button key" disabled={!connected} onClick={() => sendKey(keys.escape, "Escape")}>Esc</button><button className="button key" disabled={!connected} onClick={() => sendKey(keys.backspace, "Backspace")}>Backspace</button><button className="button key" disabled={!connected} onClick={() => sendKey(keys.enter, "Enter")}>Enter ↵</button></div><p className="input-note">Paste updates the remote clipboard. New lines in typed text send Enter.</p></div>
      </section>}
      <footer className="desktop-footer"><span role="status">{feedback || "Closing this tab leaves the browser running."}</span><span className="desktop-footer-private"><Icon name="lock" size={12} /> Private connection</span></footer>
    </main>
  );
}
