import { describe, expect, it } from 'vitest';
import { normalizeApplicationRule, macApplicationFromPath } from '../src/main/macos/processes';
import { ADMIN_LAUNCH_SCRIPT, quoteShellArgument } from '../src/main/macos/helperClient';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('macOS application routing', () => {
  it('matches an entire app bundle including nested helper processes', () => {
    expect(normalizeApplicationRule('/Applications/Google Chrome.app')).toBe('/Applications/Google Chrome.app/');
    expect(normalizeApplicationRule('/Applications/Google Chrome.app/')).toBe('/Applications/Google Chrome.app/');
    expect(normalizeApplicationRule('/usr/bin/curl')).toBe('/usr/bin/curl');
    expect(normalizeApplicationRule('Safari')).toBe('Safari');
  });
  it('rejects relative paths, traversal and control characters', () => {
    for (const value of ['../bin/curl', '/Applications/../bin/curl', '/Applications/./Safari.app', '/bin/a\n', '']) {
      expect(normalizeApplicationRule(value)).toBeNull();
    }
  });
  it('resolves a real executable instead of trusting the display name', async () => {
    expect(await macApplicationFromPath('/usr/bin/curl')).toEqual({ name: 'curl', path: '/usr/bin/curl' });
  });
});

describe('privileged launcher quoting', () => {
  it('compiles the actual administrator launcher without executing it', () => {
    const directory = mkdtempSync(join(tmpdir(), 'levik-launcher-test-'));
    try {
      expect(() => execFileSync('/usr/bin/osacompile', ['-o', join(directory, 'launcher.scpt'), '-e', ADMIN_LAUNCH_SCRIPT])).not.toThrow();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it('keeps shell metacharacters literal in the authorized executable path', () => {
    expect(quoteShellArgument("/Applications/Levik's VPN $(id).app/helper")).toBe("'/Applications/Levik'\\''s VPN $(id).app/helper'");
    expect(() => quoteShellArgument('/tmp/evil\0file')).toThrow();
  });
});
