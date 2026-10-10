import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { networkTypeOfInterface } from '../telemetry/codes';

const execute = promisify(execFile);

/**
 * The kind of physical network behind the default route, for connection
 * quality reports. Only meaningful before the tunnel owns the default route.
 */
export async function defaultRouteNetworkType(): Promise<ReturnType<typeof networkTypeOfInterface> | null> {
  try {
    const route = await execute('/sbin/route', ['-n', 'get', 'default'], { timeout: 2_000 });
    const device = /^\s*interface:\s*(\S+)\s*$/m.exec(route.stdout)?.[1];
    if (!device) return 'unknown';
    if (/^utun\d+$/.test(device)) return null;
    const ports = await execute('/usr/sbin/networksetup', ['-listallhardwareports'], { timeout: 2_000 });
    return networkTypeOfInterface(hardwarePortOf(ports.stdout, device));
  } catch {
    return 'unknown';
  }
}

/** Finds "Hardware Port: Wi-Fi" for "Device: en0" in networksetup output. */
export function hardwarePortOf(listing: string, device: string): string | null {
  for (const block of listing.split(/\n\s*\n/)) {
    const port = /^Hardware Port:\s*(.+)$/m.exec(block)?.[1]?.trim();
    const name = /^Device:\s*(\S+)$/m.exec(block)?.[1];
    if (port && name === device) return port;
  }
  return null;
}
