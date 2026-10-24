import { execFile } from "node:child_process";

/**
 * The quarantine mark macOS gives downloads: Gatekeeper then checks a file
 * received through LevikDrop like one from the internet.
 */
export function markDownloaded(path: string): Promise<void> {
  const flags = "0083";
  const stamp = Math.floor(Date.now() / 1_000).toString(16);
  return new Promise((resolve) => {
    execFile("/usr/bin/xattr", ["-w", "com.apple.quarantine", `${flags};${stamp};Levik VPN;`, path], { timeout: 5_000 }, () => resolve());
  });
}
