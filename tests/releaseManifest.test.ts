import { expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
it('publishes only matching versions and requires complete architecture pairs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'levik-manifest-'));
  try {
    for (const name of ['LevikVPN-macOS-1.0.0-arm64.dmg', 'LevikVPN-macOS-1.0.0-arm64.zip', 'LevikVPN-macOS-0.9.0-arm64.zip']) writeFileSync(join(directory, name), name);
    execFileSync(process.execPath, ['scripts/release-manifest.mjs', directory, '1.0.0']);
    const manifest: { version: string; files: { url: string }[] } = JSON.parse(readFileSync(join(directory, 'latest-mac.yml'), 'utf8'));
    expect(manifest.version).toBe('1.0.0');
    expect(manifest.files.map((file) => file.url)).toEqual(['LevikVPN-macOS-1.0.0-arm64.zip']);
    expect(readFileSync(join(directory, 'SHA256SUMS.txt'), 'utf8')).not.toContain('0.9.0');
    writeFileSync(join(directory, 'LevikVPN-macOS-1.0.0-x64.zip'), 'archive');
    expect(() => execFileSync(process.execPath, ['scripts/release-manifest.mjs', directory, '1.0.0'], { stdio: 'pipe' })).toThrow();
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
