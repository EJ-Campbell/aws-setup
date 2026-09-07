"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { KeyboardEvent, PointerEvent } from "react";
import type { BrowserInstance } from "../../../lib/contracts";
import { createReconnectLoop } from "../../../lib/reconnect.mjs";
import { fittedSize, framePoint, isPasteShortcut, modifiersFor, navigationUrl, pageMessage, physicalKey, wheelPixels } from "../../../lib/page-viewer.mjs";
import { Icon } from "../../ui";
import "../../mac-browser.css";

type Command = { type: string; [field: string]: string | number | undefined };
type Frame = { type: "frame"; data: string; width: number; height: number };
type Tab = { id: string; title: string; url: string };
type Message = Frame | { type: "tabs"; tabs: Tab[]; activeId: string; canGoBack: boolean } | { type: "error"; message: string };
type Connection = "connecting" | "connected" | "disconnected";
type Point = { x: number; y: number };
type Gesture = { id: number; startX: number; startY: number; lastX: number; lastY: number; scrolling: boolean };
const specialKeys = ["Enter", "Tab", "Escape", "Backspace", "ArrowLeft", "ArrowDown", "ArrowUp", "ArrowRight"];
const keyLabels: Record<string, string> = { Enter: "Enter ↵", Escape: "Esc", Backspace: "⌫", ArrowLeft: "←", ArrowDown: "↓", ArrowUp: "↑", ArrowRight: "→" };

export default function PageDesktop({ name }: { name: string }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const stage = useRef<HTMLDivElement>(null);
  const addressInput = useRef<HTMLInputElement>(null);
  const textInput = useRef<HTMLTextAreaElement>(null);
  const socket = useRef<WebSocket | null>(null);
  const reconnect = useRef<() => void>(() => {});
  const dimensions = useRef({ width: 1440, height: 900 });
  const ready = useRef(false);
  const activeTab = useRef("");
  const addressEditing = useRef(false);
  const pressedKeys = useRef(new Map<string, Command>());
  const pressedMouse = useRef<(Point & { button: string }) | null>(null);
  const touches = useRef(new Set<number>());
  const gesture = useRef<Gesture | null>(null);
  const motion = useRef<Command | null>(null);
  const motionTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const viewportRequest = useRef<AbortController | null>(null);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [authExpired, setAuthExpired] = useState(false);
  const [retryDelay, setRetryDelay] = useState<number | null>(null);
  const [foreground, setForeground] = useState(true);
  const [detail, setDetail] = useState("");
  const [feedback, setFeedback] = useState("");
  const [label, setLabel] = useState(name);
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeId, setActiveId] = useState("");
  const [canGoBack, setCanGoBack] = useState(false);
  const [address, setAddress] = useState("");
  const [hasFrame, setHasFrame] = useState(false);
  const [frameSize, setFrameSize] = useState(dimensions.current);
  const [available, setAvailable] = useState({ width: 1, height: 1 });
  const [fit, setFit] = useState(true);
  const [keyboard, setKeyboard] = useState(false);
  const [text, setText] = useState("");
  const [viewport, setViewport] = useState<BrowserInstance["viewport"] | null>(null);
  const [viewportPending, setViewportPending] = useState(false);
  const connected = connection === "connected";
  const phoneMode = viewport?.mode === "phone";
  const displaySize = fittedSize(available, frameSize, fit);

  const send = useCallback((command: Command) => {
    const current = socket.current;
    if (!current || current.readyState !== WebSocket.OPEN || current.bufferedAmount > 64 * 1024) return false;
    current.send(JSON.stringify(command));
    return true;
  }, []);

  const flushMotion = useCallback(() => {
    clearTimeout(motionTimer.current);
    motionTimer.current = undefined;
    if (motion.current) send(motion.current);
    motion.current = null;
  }, [send]);

  const queueMotion = useCallback((command: Command) => {
    if (command.action === "wheel" && motion.current?.action === "wheel") {
      command.deltaX = wheelPixels(Number(command.deltaX) + Number(motion.current.deltaX), 0, dimensions.current.height);
      command.deltaY = wheelPixels(Number(command.deltaY) + Number(motion.current.deltaY), 0, dimensions.current.height);
    }
    motion.current = command;
    // Coalesce high-rate trackpads/pointer moves below the server command budget.
    if (!motionTimer.current) motionTimer.current = setTimeout(flushMotion, 40);
  }, [flushMotion]);

  const releaseInputs = useCallback(() => {
    clearTimeout(motionTimer.current);
    motionTimer.current = undefined;
    motion.current = null;
    for (const command of pressedKeys.current.values()) send({ ...command, action: "up", modifiers: 0 });
    pressedKeys.current.clear();
    const mouse = pressedMouse.current;
    if (mouse) send({ type: "mouse", action: "up", button: mouse.button, modifiers: 0,
      x: Math.min(mouse.x, dimensions.current.width - 1), y: Math.min(mouse.y, dimensions.current.height - 1) });
    pressedMouse.current = null;
    touches.current.clear();
    gesture.current = null;
  }, [send]);

  useEffect(() => {
    const element = stage.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setAvailable({ width: entry.contentRect.width, height: entry.contentRect.height }));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (keyboard) textInput.current?.focus();
  }, [keyboard]);

  useEffect(() => {
    if (!connected) return;
    const controller = new AbortController();
    void fetch("/api/browsers", { cache: "no-store", signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error("Could not read browser details. Reload to renew your sign-in.");
      const data: { browsers: BrowserInstance[] } = await response.json();
      const browser = data.browsers.find(browser => browser.name === name);
      if (!controller.signal.aborted && browser) { setLabel(browser.label ?? name); setViewport(browser.viewport); }
    }).catch(error => { if (!controller.signal.aborted) setFeedback(error.message); });
    return () => controller.abort();
  }, [name, connected]);

  useEffect(() => {
    let disposed = false;
    let generation = 0;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const isActive = () => document.visibilityState === "visible" && document.hasFocus();
    const loop = createReconnectLoop(connect, setRetryDelay, isActive());
    reconnect.current = loop.retry;
    setLabel(name);
    setTabs([]);
    setActiveId("");
    setAuthExpired(false);
    function connect() {
      if (!isActive()) { loop.setActive(false); return; }
      const attempt = ++generation;
      releaseInputs();
      socket.current?.close();
      ready.current = false;
      setHasFrame(false);
      setConnection("connecting");
      setDetail("");
      clearTimeout(timeout);
      const current = () => !disposed && generation === attempt;
      const url = new URL(`/browsers/${encodeURIComponent(name)}/page`, window.location.href);
      url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const next = new WebSocket(url);
      socket.current = next;
      let failed = false;
      let pendingFrame: Frame | null = null;
      let decoding = false;
      let tabEpoch = 0;
      const fail = (message: string, expired = false) => {
        if (!current() || failed) return;
        failed = true;
        clearTimeout(timeout);
        releaseInputs();
        ready.current = false;
        setHasFrame(false);
        setConnection("disconnected");
        setDetail(message);
        if (expired) { setAuthExpired(true); loop.dispose(); }
        else loop.disconnected();
      };
      timeout = setTimeout(() => {
        fail("The browser connection timed out. Check that it is running, or reload to sign in again.");
        next.close();
      }, 15_000);

      const paint = () => {
        if (!pendingFrame || decoding || !current() || failed) return;
        const frame = pendingFrame;
        pendingFrame = null;
        decoding = true;
        const epoch = tabEpoch;
        const image = new Image();
        image.onload = () => {
          decoding = false;
          if (!current() || failed) return;
          if (epoch === tabEpoch && canvas.current) {
            const target = canvas.current;
            if (target.width !== frame.width || target.height !== frame.height) {
              target.width = frame.width;
              target.height = frame.height;
              dimensions.current = { width: frame.width, height: frame.height };
              releaseInputs();
              setFrameSize(dimensions.current);
              // A second viewer may resize the shared browser. Derive the supported
              // mode from the arriving CSS viewport instead of leaving a stale toggle.
              if (frame.width >= 320 && frame.width <= 500 && frame.height >= 480 && frame.height <= 900) {
                setViewport({ mode: "phone", width: frame.width, height: frame.height });
              } else if (frame.width === 1440 && frame.height === 900) {
                setViewport({ mode: "desktop", width: frame.width, height: frame.height });
              }
            }
            target.getContext("2d", { alpha: false })?.drawImage(image, 0, 0, frame.width, frame.height);
            ready.current = true;
            setHasFrame(true);
          }
          paint();
        };
        image.onerror = () => {
          decoding = false;
          if (current()) { setFeedback("A page frame could not be decoded. Reconnect if the image does not recover."); paint(); }
        };
        image.src = `data:image/jpeg;base64,${frame.data}`;
      };
      next.onopen = () => {
        if (!current()) return;
        clearTimeout(timeout);
        loop.connected();
        setConnection("connected");
      };
      next.onmessage = event => {
        if (!current() || failed) return;
        const message = pageMessage(event.data) as Message | null;
        if (!message) return;
        if (message.type === "frame") { pendingFrame = message; paint(); }
        else if (message.type === "tabs") {
          if (activeTab.current !== message.activeId) {
            releaseInputs();
            activeTab.current = message.activeId;
            tabEpoch++;
            pendingFrame = null;
            ready.current = false;
            setHasFrame(false);
            const target = canvas.current;
            if (target) target.getContext("2d")?.clearRect(0, 0, target.width, target.height);
          }
          setTabs(message.tabs);
          setActiveId(message.activeId);
          setCanGoBack(message.canGoBack);
          if (!addressEditing.current) setAddress(message.tabs.find(tab => tab.id === message.activeId)?.url ?? "");
        } else setFeedback(message.message);
      };
      next.onclose = event => fail([1008, 4401, 4403].includes(event.code)
        ? "Your access was closed. Reload to sign in again."
        : "The page connection closed. Your Mac browser may still be running. Reconnect, or reload to renew your sign-in.",
      [1008, 4401, 4403].includes(event.code));
      next.onerror = () => { fail("Could not reach this browser. Check that it is running, or reload to renew your sign-in."); next.close(); };
    }
    const activityChanged = () => {
      const active = isActive();
      if (!active) releaseInputs();
      setForeground(active);
      loop.setActive(active);
    };
    const suspended = () => { releaseInputs(); setForeground(false); loop.setActive(false); };
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
      releaseInputs();
      loop.dispose();
      reconnect.current = () => {};
      socket.current?.close();
      socket.current = null;
      ready.current = false;
      viewportRequest.current?.abort();
      document.removeEventListener("visibilitychange", activityChanged);
      window.removeEventListener("focus", activityChanged);
      window.removeEventListener("blur", activityChanged);
      window.removeEventListener("pageshow", activityChanged);
      window.removeEventListener("pagehide", suspended);
    };
  }, [name, releaseInputs]);

  useEffect(() => {
    const target = canvas.current;
    if (!target) return;
    const wheel = (event: WheelEvent) => {
      if (!ready.current) return;
      const point = framePoint(event.clientX, event.clientY, target.getBoundingClientRect(), dimensions.current);
      if (!point) return;
      event.preventDefault();
      queueMotion({ type: "mouse", action: "wheel", ...point, button: "left", modifiers: modifiersFor(event),
        deltaX: wheelPixels(event.deltaX, event.deltaMode, dimensions.current.height),
        deltaY: wheelPixels(event.deltaY, event.deltaMode, dimensions.current.height) });
    };
    target.addEventListener("wheel", wheel, { passive: false });
    return () => target.removeEventListener("wheel", wheel);
  }, [queueMotion]);

  function pointFor(event: PointerEvent<HTMLCanvasElement>, clamp = false) {
    return framePoint(event.clientX, event.clientY, event.currentTarget.getBoundingClientRect(), dimensions.current, clamp);
  }

  function pointerDown(event: PointerEvent<HTMLCanvasElement>) {
    if (!ready.current) return;
    const point = pointFor(event);
    if (!point) return;
    event.preventDefault();
    event.currentTarget.focus({ preventScroll: true });
    event.currentTarget.setPointerCapture(event.pointerId);
    if (event.pointerType === "touch") {
      touches.current.add(event.pointerId);
      gesture.current = touches.current.size === 1 ? { id: event.pointerId, startX: event.clientX, startY: event.clientY,
        lastX: event.clientX, lastY: event.clientY, scrolling: false } : null;
      return;
    }
    flushMotion();
    const button = event.button === 2 ? "right" : event.button === 1 ? "middle" : "left";
    pressedMouse.current = { ...point, button };
    send({ type: "mouse", action: "down", ...point, button, modifiers: modifiersFor(event) });
  }

  function pointerMove(event: PointerEvent<HTMLCanvasElement>) {
    if (!ready.current) return;
    const point = pointFor(event, Boolean(pressedMouse.current || gesture.current));
    if (!point) return;
    if (event.pointerType === "touch") {
      const active = gesture.current;
      if (!active || active.id !== event.pointerId) return;
      if (Math.hypot(event.clientX - active.startX, event.clientY - active.startY) > 7) active.scrolling = true;
      if (active.scrolling) {
        const bounds = event.currentTarget.getBoundingClientRect();
        queueMotion({ type: "mouse", action: "wheel", ...point, button: "left", modifiers: 0,
          deltaX: wheelPixels((active.lastX - event.clientX) * dimensions.current.width / bounds.width, 0, dimensions.current.height),
          deltaY: wheelPixels((active.lastY - event.clientY) * dimensions.current.height / bounds.height, 0, dimensions.current.height) });
      }
      active.lastX = event.clientX;
      active.lastY = event.clientY;
      return;
    }
    if (pressedMouse.current) pressedMouse.current = { ...pressedMouse.current, ...point };
    queueMotion({ type: "mouse", action: "move", ...point, button: pressedMouse.current?.button ?? "left", modifiers: modifiersFor(event) });
  }

  function pointerUp(event: PointerEvent<HTMLCanvasElement>) {
    const point = pointFor(event, true);
    flushMotion();
    if (event.pointerType === "touch") {
      const active = gesture.current;
      touches.current.delete(event.pointerId);
      if (active?.id === event.pointerId && !active.scrolling && point && ready.current) {
        send({ type: "mouse", action: "down", ...point, button: "left", modifiers: 0 });
        send({ type: "mouse", action: "up", ...point, button: "left", modifiers: 0 });
      }
      gesture.current = null;
    } else if (pressedMouse.current) {
      if (point) send({ type: "mouse", action: "up", ...point, button: pressedMouse.current.button, modifiers: modifiersFor(event) });
      pressedMouse.current = null;
    }
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  }

  function keyDown(event: KeyboardEvent<HTMLCanvasElement>) {
    if (!ready.current) return;
    event.preventDefault();
    const shortcut = event.ctrlKey || event.metaKey;
    if (isPasteShortcut(event)) {
      setKeyboard(true);
      setFeedback("Paste into the text box, then choose Send text. Clipboard contents are never shared automatically.");
      return;
    }
    if (shortcut && event.key.toLowerCase() === "l") { addressInput.current?.focus(); addressInput.current?.select(); return; }
    if (shortcut && event.key.toLowerCase() === "t") { send({ type: "newTab", url: "about:blank" }); return; }
    if (shortcut && event.key.toLowerCase() === "w") { if (activeId) send({ type: "closeTab", id: activeId }); return; }
    const command = physicalKey(event.nativeEvent, "down");
    if (!command) { setFeedback("For composed or international text, use Keyboard → Send text."); return; }
    if (command.type === "key") pressedKeys.current.set(event.code, command);
    send(command);
    if (event.key === "Escape") event.currentTarget.blur();
  }

  function keyUp(event: KeyboardEvent<HTMLCanvasElement>) {
    const command = pressedKeys.current.get(event.code);
    if (!command) return;
    event.preventDefault();
    send({ ...command, action: "up", modifiers: modifiersFor(event) });
    pressedKeys.current.delete(event.code);
  }

  function keyTap(key: string) {
    if (!ready.current) return;
    send({ type: "key", action: "down", key, code: key, modifiers: 0 });
    send({ type: "key", action: "up", key, code: key, modifiers: 0 });
  }

  async function togglePhoneMode() {
    if (!connected || !viewport || viewportRequest.current) return;
    const controller = new AbortController();
    viewportRequest.current = controller;
    setViewportPending(true);
    releaseInputs();
    const mobile = window.innerWidth <= 700;
    const requested = phoneMode ? { mode: "desktop" } : { mode: "phone",
      width: mobile ? Math.max(320, Math.min(500, Math.round(available.width))) : 390,
      height: mobile ? Math.max(480, Math.min(900, Math.round(available.height))) : 844 };
    try {
      const response = await fetch(`/api/browsers/${encodeURIComponent(name)}/viewport`, { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify(requested), signal: controller.signal });
      if (!response.ok) throw new Error("Could not resize this browser. Reconnect, or reload to renew your sign-in.");
      const data: { browser: BrowserInstance } = await response.json();
      if (!controller.signal.aborted) {
        setViewport(data.browser.viewport);
        setFit(true);
        setFeedback("Page width changed for every viewer of this browser. This is not an iOS emulator.");
      }
    } catch (error) { if (!controller.signal.aborted) setFeedback(error instanceof Error ? error.message : "Could not resize this page."); }
    finally { if (viewportRequest.current === controller) { viewportRequest.current = null; setViewportPending(false); } }
  }

  return <main className="mac-browser" data-transport="page">
    <header className="mac-browser-header">
      <a className="icon-button" href="/" aria-label="All browsers" title="All browsers"><Icon name="back" /></a>
      <div className="mac-browser-title"><h1>{label}</h1><div className="connection-status" role="status" data-state={connection}><span />
        {authExpired ? "Sign in again" : connected ? "Connected · Mac Chrome" : connection === "connecting" ? "Connecting…" : "Disconnected"}</div></div>
      <div className="mac-browser-tools">
        <button className="button" onClick={() => void togglePhoneMode()} disabled={!connected || !viewport || viewportPending} aria-label="Phone mode" aria-pressed={Boolean(phoneMode)} title="Resize the shared page; no browser restart"><Icon name="phone" size={18} /><span>Phone</span></button>
        <button className="button" onClick={() => setFit(value => !value)} aria-pressed={fit} title="Scale only this viewer"><Icon name="fit" size={18} /><span>Fit</span></button>
        <button className="button" onClick={() => setKeyboard(value => !value)} aria-pressed={keyboard}><Icon name="keyboard" size={18} /><span>Keyboard</span></button>
      </div>
    </header>
    <nav className="mac-tabs" aria-label="Remote browser tabs">
      <div className="mac-tab-list" role="tablist" aria-label="Open Mac Chrome pages">{tabs.map(tab => <div className="mac-tab" key={tab.id} data-active={tab.id === activeId}>
        <button role="tab" aria-selected={tab.id === activeId} title={tab.url} disabled={!connected} onClick={() => { releaseInputs(); send({ type: "selectTab", id: tab.id }); }}>
          <Icon name="browser" size={15} /><span>{tab.title || "New tab"}</span></button>
        <button className="mac-tab-close" aria-label={`Close tab ${tab.title || "New tab"}`} disabled={!connected} onClick={() => send({ type: "closeTab", id: tab.id })}><Icon name="close" size={15} /></button>
      </div>)}</div>
      <button className="icon-button" aria-label="New tab" disabled={!connected} onClick={() => send({ type: "newTab", url: "about:blank" })}><Icon name="plus" size={20} /></button>
    </nav>
    <form className="mac-navigation" onSubmit={event => {
      event.preventDefault();
      try { const url = navigationUrl(address); if (send({ type: "navigate", url })) { setAddress(url); addressEditing.current = false; addressInput.current?.blur(); } }
      catch (error) { setFeedback(error instanceof Error ? error.message : "Enter a valid address."); }
    }}>
      <button type="button" className="icon-button" aria-label="Back in remote browser" title="Back" disabled={!connected || !canGoBack} onClick={() => send({ type: "back" })}><Icon name="back" size={20} /></button>
      <button type="button" className="icon-button mac-forward" aria-label="Forward in remote browser" title="Forward" disabled={!connected || !activeId} onClick={() => send({ type: "forward" })}><Icon name="back" size={20} /></button>
      <button type="button" className="icon-button" aria-label="Reload remote page" title="Reload remote page" disabled={!connected || !activeId} onClick={() => send({ type: "reload" })}><Icon name="refresh" size={19} /></button>
      <label className="sr-only" htmlFor="remote-page-address">Remote page address</label>
      <input ref={addressInput} id="remote-page-address" value={address} onChange={event => setAddress(event.target.value)} onFocus={() => { addressEditing.current = true; }} onBlur={() => { addressEditing.current = false; }} type="text" inputMode="url" enterKeyHint="go" autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="Enter a website address" disabled={!connected || !activeId} maxLength={2048} />
      <button type="submit" className="icon-button" aria-label="Go to address" disabled={!connected || !activeId}><Icon name="arrow" size={20} /></button>
    </form>
    {feedback && <div className="mac-feedback" role="status"><span>{feedback}</span><button className="icon-button" aria-label="Dismiss message" onClick={() => setFeedback("")}><Icon name="close" size={17} /></button></div>}
    <div className="mac-page-stage" ref={stage} data-fit={fit}>
      <canvas className="mac-page-canvas" ref={canvas} width={1440} height={900} tabIndex={connected && hasFrame ? 0 : -1}
        role="application" aria-label="Remote Mac Chrome page. Click to control; Escape releases keyboard focus. On touch screens, tap to click and drag to scroll."
        style={displaySize} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerCancel={releaseInputs}
        onLostPointerCapture={() => { if (pressedMouse.current) releaseInputs(); }} onContextMenu={event => event.preventDefault()} onKeyDown={keyDown} onKeyUp={keyUp} onBlur={releaseInputs} />
      {(!connected || !hasFrame) && <div className="connection-overlay"><div className="connection-card">
        {connection === "connecting" || connected ? <span className="spinner" /> : <Icon name="browser" size={42} />}
        <h2>{authExpired ? "Sign in to reconnect" : connected ? "Waiting for the page" : connection === "connecting" ? "Connecting to Mac Chrome" : "Browser disconnected"}</h2>
        <p>{detail || (connected ? "Only the selected webpage is streamed. Your Mac desktop and other apps are not shared." : "Your browser and saved logins stay on the Mac.")}</p>
        {retryDelay && !authExpired && <p>Retrying in {retryDelay} seconds…</p>}
        {!foreground && <p>Automatic reconnect pauses while this tab is in the background.</p>}
        <div className="connection-actions">{!authExpired && <button className="button primary" onClick={() => reconnect.current()}>Reconnect</button>}
          <button className="button" onClick={() => window.location.reload()}>Reload / sign in</button><a className="button" href="/">All browsers</a></div>
      </div></div>}
    </div>
    {keyboard && <section className="mac-keyboard" aria-label="Remote page keyboard controls">
      <div className="mac-keyboard-heading"><div><h2>Send text to the page</h2><p>Tap a field in the remote page first. Nothing is sent until you choose Send text.</p></div>
        <button className="icon-button" aria-label="Close keyboard controls" onClick={() => setKeyboard(false)}><Icon name="close" size={20} /></button></div>
      <div className="mac-text-row"><textarea ref={textInput} aria-label="Text for the remote page" value={text} maxLength={4096} rows={2} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={event => setText(event.target.value)} placeholder="Type or paste here…" />
        <button className="button primary" disabled={!connected || !hasFrame || !text} onClick={() => {
          if (send({ type: "text", text })) { setText(""); setFeedback("Text sent to the selected page field."); }
        }}>Send text</button></div>
      <div className="mac-special-keys">{specialKeys.map(key => <button className="button" key={key} aria-label={keyLabels[key] || key} disabled={!connected || !hasFrame} onClick={() => keyTap(key)}>{keyLabels[key] || key}</button>)}</div>
    </section>}
    <footer className="mac-browser-footer"><span>Webpage only · Tabs and Phone mode are shared with other viewers.</span><span>{frameSize.width} × {frameSize.height}</span></footer>
  </main>;
}
