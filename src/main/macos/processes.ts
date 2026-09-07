import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { basename } from 'node:path';
import { realpath, stat } from 'node:fs/promises';
import type { MacApplication } from '../../shared/contracts';

const execute = promisify(execFile);

export function normalizeApplicationRule(value: string): string | null {
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  const path = value.trim();
  if (!path || path.length > 1024 || /[\u0000-\u001f\u007f]/.test(path)) return null;
  if (path.includes('/')) {
    if (!path.startsWith('/') || path.split('/').some((part) => part === '..' || part === '.')) return null;
    return path.endsWith('.app') ? `${path}/` : path;
  }
  return path.length <= 128 ? path : null;
}

export async function macApplicationFromPath(path: string): Promise<MacApplication | null> {
  const resolved = await realpath(path);
  const info = await stat(resolved);
  if (info.isDirectory() && resolved.endsWith('.app')) {
    return { name: basename(resolved, '.app'), path: `${resolved}/` };
  }
  if (info.isFile() && (info.mode & 0o111) !== 0 && normalizeApplicationRule(resolved)) {
    return { name: basename(resolved), path: resolved };
  }
  return null;
}

export async function listMacApplications(): Promise<MacApplication[]> {
  const { stdout } = await execute('/bin/ps', ['-axo', 'comm='], { timeout: 10_000, maxBuffer: 2 * 1024 * 1024 });
  const paths = new Set(stdout.split('\n').flatMap((line) => {
    const value = line.trim();
    const app = value.match(/^(.+?\.app)\//)?.[1];
    return app ? [app] : [];
  }));
  const results = await Promise.all([...paths].slice(0, 300).map((path) => macApplicationFromPath(path).catch(() => null)));
  return results.filter((value): value is MacApplication => value !== null).sort((a, b) => a.name.localeCompare(b.name));
}
