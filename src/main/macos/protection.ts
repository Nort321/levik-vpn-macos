import { macHelper } from './helperClient';

export class MacKillSwitch {
  private active = false;
  async recover(): Promise<boolean> {
    this.active = await macHelper.recoveredProtection();
    macHelper.killSwitch = this.active;
    return this.active;
  }
  prepareForTunnelStart(): void { macHelper.killSwitch = true; }
  async enable(): Promise<void> { macHelper.killSwitch = true; await macHelper.configure(); }
  async allowTunnel(): Promise<void> {
    if (!macHelper.killSwitch) return;
    this.active = (await macHelper.status()).killSwitch;
    if (!this.active) throw new Error('Не удалось подтвердить работу Kill Switch');
  }
  async disable(): Promise<void> {
    macHelper.killSwitch = false;
    if (!macHelper.connected && await macHelper.recoveredProtection()) await macHelper.request('protection', { killSwitch: false, dnsProtection: false });
    else await macHelper.configure();
    this.active = false;
  }
  async ensureActive(shouldRestore: () => boolean): Promise<boolean> {
    if (!macHelper.connected || !shouldRestore()) return false;
    const status = await macHelper.status();
    if (status.killSwitch) return false;
    await macHelper.configure();
    this.active = (await macHelper.status()).killSwitch;
    if (!this.active) throw new Error('Kill Switch не восстановлен');
    return true;
  }
  isActive(): boolean { return this.active; }
}

export class DnsLeakProtection {
  async enable(): Promise<void> { macHelper.dnsProtection = true; }
  async disable(): Promise<void> { macHelper.dnsProtection = false; await macHelper.configure(); }
}
