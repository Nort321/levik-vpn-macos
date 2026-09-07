import { beforeEach, expect, it, vi } from 'vitest';
const helper = vi.hoisted(() => ({ killSwitch: false, configure: vi.fn(), status: vi.fn() }));
vi.mock('../src/main/macos/helperClient', () => ({ macHelper: helper }));
import { MacKillSwitch } from '../src/main/macos/protection';
beforeEach(() => { helper.killSwitch = false; vi.clearAllMocks(); });
it('installs protection before attesting an already connected tunnel', async () => {
  helper.configure.mockImplementation(async () => { helper.status.mockResolvedValue({ killSwitch: helper.killSwitch }); });
  const protection = new MacKillSwitch();
  await protection.enable();
  await protection.allowTunnel();
  expect(helper.configure).toHaveBeenCalledOnce();
  expect(protection.isActive()).toBe(true);
});
it('propagates firewall installation errors instead of reporting protection', async () => {
  helper.configure.mockRejectedValueOnce(new Error('PF failed'));
  const protection = new MacKillSwitch();
  await expect(protection.enable()).rejects.toThrow('PF failed');
  expect(protection.isActive()).toBe(false);
});
