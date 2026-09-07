/**
 * noVNC already requests 24-bit color. Adjust JPEG quality/compression from
 * browser connection hints, not a throughput measurement; absent hints favor quality.
 * @param {{ qualityLevel: number, compressionLevel: number }} client
 * @param {{ saveData?: boolean, effectiveType?: string, downlink?: number,
 *   addEventListener?: (type: string, listener: () => void) => void,
 *   removeEventListener?: (type: string, listener: () => void) => void }} [connection]
 */
export function watchVncQuality(client, connection = globalThis.navigator?.connection) {
  const update = () => {
    const downlink = connection?.downlink;
    const constrained = connection?.saveData === true ||
      ['slow-2g', '2g', '3g'].includes(connection?.effectiveType) ||
      (Number.isFinite(downlink) && downlink > 0 && downlink < 2);
    client.qualityLevel = constrained ? 6 : 9;
    client.compressionLevel = constrained ? 6 : 2;
  };
  update();
  connection?.addEventListener?.('change', update);
  return () => connection?.removeEventListener?.('change', update);
}
