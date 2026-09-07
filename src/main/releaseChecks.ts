import { app } from 'electron';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AppController } from './appController';
import { macHelper } from './macos/helperClient';

const execute = promisify(execFile);
const sleep = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
type Result = { name: string; passed: boolean; detail: string };
type Audit = { rootRulesSHA256: string | undefined; physicalDNSPackets: number | undefined };

async function probe(args: string[], seconds = 5): Promise<{ ok: boolean; body: string; code: string }> {
  try {
    const { stdout } = await execute('/usr/bin/curl', ['--noproxy', '*', '--silent', '--show-error', '--fail', '--max-time', String(seconds), ...args], { timeout: (seconds + 2) * 1000, maxBuffer: 1024 * 1024 });
    return { ok: true, body: stdout, code: '0' };
  } catch (error) {
    const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'unknown';
    return { ok: false, body: '', code };
  }
}
function publicIP(body: string): string | undefined { return body.match(/^ip=(.+)$/m)?.[1]; }
function audit(value: unknown): Audit {
  if (typeof value !== 'object' || value === null) throw new Error('Invalid audit response');
  return {
    rootRulesSHA256: 'rootRulesSHA256' in value && typeof value.rootRulesSHA256 === 'string' ? value.rootRulesSHA256 : undefined,
    physicalDNSPackets: 'physicalDNSPackets' in value && typeof value.physicalDNSPackets === 'number' ? value.physicalDNSPackets : undefined,
  };
}

// Explicit CLI-only acceptance mode. Runs in the authorized main PID so the
// helper's UID/PID boundary stays intact. No profiles or addresses enter reports.
export async function runReleaseChecks(controller: AppController, dnsOnly = false): Promise<void> {
  const original = structuredClone(controller.snapshot().settings);
  const results: Result[] = [];
  const outputDirectory = join(app.getPath('userData'), 'diagnostics');
  await mkdir(outputDirectory, { recursive: true });
  const output = join(outputDirectory, dnsOnly ? 'release-dns-checks.json' : 'release-checks.json');
  const save = async (finished: boolean) => writeFile(output, JSON.stringify({ version: app.getVersion(), at: new Date().toISOString(), finished, results }, null, 2) + '\n', { mode: 0o600 });
  const record = async (name: string, passed: boolean, detail = '') => { results.push({ name, passed, detail }); await save(false); };
  const requireResult = async (name: string, passed: boolean, detail = '') => { await record(name, passed, detail); if (!passed) throw new Error(name); };
  const traceURL = 'https://1.1.1.1/cdn-cgi/trace';
  let initialRules: string | undefined;
  try {
    await controller.disconnect();
    await controller.updateSettings({ ...original, routingMode: 'global', splitTunnelMode: 'off', killSwitch: false, preventDnsLeaks: true, useDoh: true, autoReconnect: false, automaticServer: false, autoConnectOnLaunch: false });
    await controller.connect();
    initialRules = audit(await macHelper.request('audit-rules')).rootRulesSHA256;
    const gateway = await execute('/sbin/route', ['-n', 'get', 'default']);
    const physical = gateway.stdout.match(/interface:\s*(\w+)/)?.[1];
    const router = gateway.stdout.match(/gateway:\s*([0-9.]+)/)?.[1];
    if (!physical || !/^en\d+$/.test(physical)) throw new Error('A physical Ethernet/Wi-Fi uplink is required');
    const direct = await probe(['--interface', physical, traceURL]);
    await requireResult('direct-baseline', direct.ok && Boolean(publicIP(direct.body)), `curl=${direct.code}`);
    const tunneled = await probe([traceURL]);
    await requireResult('https-ipv4-tunnel', tunneled.ok && Boolean(publicIP(tunneled.body)) && publicIP(tunneled.body) !== publicIP(direct.body), `curl=${tunneled.code}; exit IP differs from baseline`);
    const ipv6 = await probe(['-6', 'https://[2606:4700:4700::1111]/cdn-cgi/trace']);
    await record('https-ipv6-tunnel', ipv6.ok && Boolean(publicIP(ipv6.body)), `curl=${ipv6.code}`);

    await macHelper.request('audit-start');
    try {
      const dns = await execute('/usr/bin/dig', ['+tries=1', '+time=3', '+short', '@1.1.1.1', 'example.com', 'A'], { timeout: 5000 });
      await record('udp-dns-through-tunnel', /\d+\.\d+\.\d+\.\d+/.test(dns.stdout));
      if (router) {
        const blocked = await execute('/usr/bin/dig', ['+tries=1', '+time=2', `@${router}`, 'example.com', 'A'], { timeout: 4000 }).then(() => false, () => true);
        await record('physical-router-dns-blocked', blocked);
      }
      await probe(['https://example.com']);
      await sleep(500);
    } finally {
      const capture = audit(await macHelper.request('audit-stop'));
      await record('physical-dns-packet-capture', capture.physicalDNSPackets === 0, `outbound DNS/DoT packets=${capture.physicalDNSPackets ?? 'unavailable'}`);
    }
    if (dnsOnly) return;

    await controller.updateSettings({ killSwitch: true });
    await requireResult('enable-kill-switch-while-connected', (await macHelper.status()).killSwitch);
    const guarded = await probe([traceURL]);
    await requireResult('https-with-kill-switch', guarded.ok, `curl=${guarded.code}`);
    const forbidden = await probe(['--interface', physical, traceURL], 3);
    await requireResult('physical-https-blocked', !forbidden.ok, `curl=${forbidden.code}; direct baseline succeeded`);

    await macHelper.request('abort-core');
    await sleep(2500);
    await requireResult('core-exit-retains-kill-switch', !(await macHelper.status()).running && (await macHelper.status()).killSwitch);
    const stopped = await probe([traceURL], 3);
    await requireResult('core-exit-no-ipv4-escape', !stopped.ok, `curl=${stopped.code}`);
    const stopped6 = await probe(['-6', 'https://[2606:4700:4700::1111]/cdn-cgi/trace'], 3);
    await requireResult('core-exit-no-ipv6-escape', !stopped6.ok, `curl=${stopped6.code}`);
    await controller.disconnect();
    const restored = await probe([traceURL]);
    await requireResult('disconnect-restores-network', restored.ok && publicIP(restored.body) === publicIP(direct.body), `curl=${restored.code}`);
    await controller.connect();

    await controller.updateSettings({ autoReconnect: true });
    const before = await macHelper.status();
    const bytesBefore = controller.snapshot().downloadBytes;
    await macHelper.request('abort-core');
    const deadline = Date.now() + 45000;
    let recovered = false;
    while (Date.now() < deadline) {
      await sleep(500);
      const status = await macHelper.status();
      if (status.running && status.pid !== before.pid && controller.snapshot().status === 'connected') { recovered = true; break; }
    }
    await requireResult('automatic-reconnect-after-sigkill', recovered);
    await probe([traceURL]);
    await sleep(2200);
    await record('reconnect-byte-counts-monotonic', controller.snapshot().downloadBytes >= bytesBefore);

    for (const mode of ['bypass', 'only'] as const) {
      await controller.updateSettings({ splitTunnelMode: mode, splitTunnelProcesses: ['/usr/bin/curl'] });
      const response = await probe([traceURL]);
      await record(`process-routing-${mode}`, response.ok && (mode === 'bypass' ? publicIP(response.body) === publicIP(direct.body) : publicIP(response.body) === publicIP(tunneled.body)), `curl=${response.code}`);
    }
    await controller.updateSettings({ splitTunnelMode: 'off', splitTunnelProcesses: [] });
    for (const routingMode of ['bypassRu', 'blockedOnly'] as const) {
      await controller.updateSettings({ routingMode });
      const response = await probe([traceURL]);
      await record(`routing-${routingMode}`, response.ok && (routingMode === 'blockedOnly' ? publicIP(response.body) === publicIP(direct.body) : publicIP(response.body) === publicIP(tunneled.body)), `curl=${response.code}`);
    }
  } catch (error) {
    await record('run-completed', false, error instanceof Error ? error.message : 'Acceptance run failed');
  } finally {
    try {
      await controller.disconnect();
      if (initialRules) await record('existing-pf-rules-preserved', audit(await macHelper.request('audit-rules')).rootRulesSHA256 === initialRules);
      await controller.updateSettings(original);
      await controller.connect();
      await record('settings-and-connection-restored', true);
    } catch (error) { await record('settings-and-connection-restored', false, error instanceof Error ? error.message : 'Restoration failed'); }
    await save(true);
  }
}
