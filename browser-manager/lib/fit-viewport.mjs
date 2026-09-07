/** Whether fitting changes either natural-size dimension by at least one CSS pixel. */
export function canFitViewport(width, height, availableWidth, availableHeight) {
  if (![width, height, availableWidth, availableHeight].every(value => Number.isFinite(value) && value > 0)) return false;
  const scale = Math.min(availableWidth / width, availableHeight / height);
  return Math.abs(width * scale - width) >= 1 || Math.abs(height * scale - height) >= 1;
}
