declare module "@novnc/novnc" {
  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, url: string, options?: { shared?: boolean });
    scaleViewport: boolean;
    resizeSession: boolean;
    background: string;
    focusOnClick: boolean;
    qualityLevel: number;
    compressionLevel: number;
    disconnect(): void;
    focus(): void;
    blur(): void;
    sendKey(keysym: number, code: string | null, down?: boolean): void;
    clipboardPasteFrom(text: string): void;
  }
}
