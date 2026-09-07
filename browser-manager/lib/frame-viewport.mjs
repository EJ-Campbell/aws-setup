/**
 * noVNC's intrinsic canvas dimensions are the shared framebuffer, not its local CSS scale.
 * @param {number | undefined} width
 * @param {number | undefined} height
 * @returns {{mode: 'desktop' | 'phone', width: number, height: number} | null}
 */
export function frameViewport(width, height) {
  if (!Number.isInteger(width) || !Number.isInteger(height)) return null;
  if (width === 1440 && height === 900) return { mode: 'desktop', width, height };
  if (width >= 320 && width <= 500 && height >= 480 && height <= 900) {
    return { mode: 'phone', width, height };
  }
  return null;
}
