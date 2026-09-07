"use client";

import { useEffect, useRef, useState } from "react";
import type RFB from "@novnc/novnc";
import { Icon } from "../../ui";

type Connection = "connecting" | "connected" | "disconnected" | "error";
const keys = { enter: 0xff0d, tab: 0xff09, escape: 0xff1b, backspace: 0xff08, control: 0xffe3 };

export default function Desktop({ name }: { name: string }) {
  const screen = useRef<HTMLDivElement>(null);
  const workspace = useRef<HTMLElement>(null);
  const client = useRef<RFB | null>(null);
  const textInput = useRef<HTMLTextAreaElement>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [detail, setDetail] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [fit, setFit] = useState(true);
  const [keyboard, setKeyboard] = useState(false);
  const [text, setText] = useState("");
  const [feedback, setFeedback] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
  const [canFullscreen, setCanFullscreen] = useState(false);
  const connected = connection === "connected";

  useEffect(() => {
    let disposed = false;
    let rfb: RFB | undefined;
    setConnection("connecting");
    setDetail("");
    void import("@novnc/novnc").then(({ default: RFBClient }) => {
      if (disposed || !screen.current) return;
      const url = new URL(`/browsers/${encodeURIComponent(name)}/vnc`, window.location.href);
      url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      rfb = new RFBClient(screen.current, url.href, { shared: true });
      rfb.scaleViewport = true;
      // Scaling is local: one viewer must not resize another viewer's desktop.
      rfb.resizeSession = false;
      rfb.background = "#171d25";
      rfb.focusOnClick = true;
      client.current = rfb;
      rfb.addEventListener("connect", () => {
        if (!disposed) { setConnection("connected"); setDetail(""); }
      });
      rfb.addEventListener("disconnect", (event) => {
        if (disposed) return;
        const clean = (event as CustomEvent<{ clean: boolean }>).detail.clean;
        setConnection((current) => current === "error" ? current : "disconnected");
        setDetail((current) => current || (clean
          ? "The desktop connection closed. Your browser may still be running."
          : "Could not reach this desktop. Check that it is running, or reload to renew your sign-in."));
      });
      const authenticationFailure = () => {
        if (disposed) return;
        setConnection("error");
        setDetail("The desktop rejected the connection. Return to your browsers and check its status.");
        rfb?.disconnect();
      };
      rfb.addEventListener("credentialsrequired", authenticationFailure);
      rfb.addEventListener("securityfailure", authenticationFailure);
    }).catch(() => {
      if (!disposed) {
        setConnection("error");
        setDetail("The desktop viewer could not load. Reload this page to try again.");
      }
    });
    return () => {
      disposed = true;
      client.current = null;
      rfb?.disconnect();
    };
  }, [name, attempt]);

  useEffect(() => { if (client.current) client.current.scaleViewport = fit; }, [fit, connection]);
  useEffect(() => {
    setCanFullscreen(Boolean(document.fullscreenEnabled && workspace.current?.requestFullscreen));
    const changed = () => setFullscreen(document.fullscreenElement === workspace.current);
    document.addEventListener("fullscreenchange", changed);
    return () => document.removeEventListener("fullscreenchange", changed);
  }, []);
  useEffect(() => {
    if (keyboard) { client.current?.blur(); textInput.current?.focus(); }
  }, [keyboard]);

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
        <div className="desktop-title"><h1>{name}</h1><span className="connection-status" data-state={connection} role="status"><span />{connected ? "Connected" : connection === "connecting" ? "Connecting…" : "Disconnected"}</span></div>
        <div className="desktop-toolbar" aria-label="Desktop controls">
          <button className="button quiet" aria-pressed={fit} onClick={() => setFit(!fit)} title={fit ? "Show desktop at actual size" : "Fit desktop to screen"}><Icon name="fit" size={18} /><span>Fit to screen</span></button>
          <button className="button quiet" aria-pressed={keyboard} aria-controls="keyboard-panel" onClick={() => setKeyboard(!keyboard)}><Icon name="keyboard" size={18} /><span>Keyboard</span></button>
          <button className="button quiet" disabled={!canFullscreen} onClick={() => void toggleFullscreen()} title={canFullscreen ? "Toggle fullscreen" : "Fullscreen is not supported in this browser"} aria-label={fullscreen ? "Exit fullscreen" : "Enter fullscreen"}><Icon name="expand" size={18} /><span className="fullscreen-label">{fullscreen ? "Exit fullscreen" : "Fullscreen"}</span></button>
          <button className="button quiet" onClick={() => setAttempt((value) => value + 1)} disabled={connection === "connecting"} aria-label="Reconnect desktop"><Icon name="refresh" size={18} /><span>Reconnect</span></button>
        </div>
      </header>

      <section className="desktop-display" aria-label={`${name} remote desktop`}>
        <div ref={screen} className="vnc-screen" />
        {!connected && <div className={`connection-overlay${keyboard ? " compact" : ""}`}><div className="connection-card">
          {connection === "connecting" ? <span className="spinner" aria-hidden="true" /> : <Icon name="browser" size={32} />}
          <h2>{connection === "connecting" ? "Connecting to your desktop" : "Desktop disconnected"}</h2>
          <p>{detail || "Opening a private connection to your browser."}</p>
          {connection !== "connecting" && <div className="connection-actions"><button className="button primary" onClick={() => setAttempt((value) => value + 1)}>Reconnect</button><a className="button" href="/">Your browsers</a></div>}
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
