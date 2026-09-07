// Native Chromium and Xvfb share this fixed density; API dimensions stay logical CSS pixels.
export const VNC_PIXEL_RATIO = 2;

/**
 * Decode the shared physical framebuffer into logical viewport dimensions.
 * Legacy 1x frames remain recognizable while existing viewers/desktops reconnect during rollout.
 * @param {number | undefined} width
 * @param {number | undefined} height
 * @returns {{mode: 'desktop' | 'phone', width: number, height: number} | null}
 */
export function frameViewport(width, height) {
  if (!Number.isInteger(width) || !Number.isInteger(height)) return null;
  for (const density of [VNC_PIXEL_RATIO, 1]) {
    const logicalWidth = width / density, logicalHeight = height / density;
    if (!Number.isInteger(logicalWidth) || !Number.isInteger(logicalHeight)) continue;
    if (logicalWidth === 1440 && logicalHeight === 900) {
      return { mode: 'desktop', width: logicalWidth, height: logicalHeight };
    }
    if (logicalWidth >= 320 && logicalWidth <= 500 && logicalHeight >= 480 && logicalHeight <= 900) {
      return { mode: 'phone', width: logicalWidth, height: logicalHeight };
    }
  }
  return null;
}
