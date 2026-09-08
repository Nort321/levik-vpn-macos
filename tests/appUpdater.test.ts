import { beforeEach, describe, expect, it, vi } from "vitest";

type UpdateListener = (...args: unknown[]) => void;

const updaterMock = vi.hoisted(() => {
  const listeners = new Map<string, UpdateListener[]>();
  const autoUpdater = {
    autoDownload: true,
    autoInstallOnAppQuit: true,
    allowPrerelease: true,
    setFeedURL: vi.fn(),
    checkForUpdates: vi.fn(async () => null),
    downloadUpdate: vi.fn(async () => ["update.zip"]),
    on: vi.fn((event: string, listener: UpdateListener) => {
      listeners.set(event, [...(listeners.get(event) ?? []), listener]);
      return autoUpdater;
    }),
  };
  return {
    autoUpdater,
    emit(event: string, ...args: unknown[]) {
      for (const listener of listeners.get(event) ?? []) listener(...args);
    },
    reset() {
      listeners.clear();
      autoUpdater.setFeedURL.mockClear();
      autoUpdater.checkForUpdates.mockClear();
      autoUpdater.downloadUpdate.mockClear();
      autoUpdater.on.mockClear();
      autoUpdater.downloadUpdate.mockResolvedValue(["/tmp/LevikVPN-macOS-1.2.8-arm64.zip"]);
    },
  };
});

const appMock = vi.hoisted(() => ({ quit: vi.fn() }));
const installerMock = vi.hoisted(() => ({
  verifyDownloadedUpdate: vi.fn(async (_paths: string[], info: { version: string }) => ({ archivePath: "/tmp/LevikVPN-macOS-1.2.8-arm64.zip", version: info.version, sha512: "checksum" })),
  prepareMacUpdate: vi.fn(async (update: object) => ({ ...update, bundlePath: "/tmp/staging/Levik VPN.app", stagingRoot: "/tmp/staging" })),
  launchMacUpdateInstaller: vi.fn(async () => undefined),
  cleanupPreparedMacUpdate: vi.fn(async () => undefined),
}));

vi.mock("electron", () => ({
  app: { isPackaged: true, getVersion: () => "1.2.7", quit: appMock.quit },
}));

vi.mock("electron-updater", () => ({ autoUpdater: updaterMock.autoUpdater }));
vi.mock("../src/main/update/macUpdateInstaller", () => installerMock);

import { AppUpdater } from "../src/main/update/appUpdater";

describe("macOS OTA updater", () => {
  beforeEach(() => {
    delete process.env.LEVIK_UPDATE_URL;
    updaterMock.reset();
    appMock.quit.mockClear();
    vi.clearAllMocks();
  });

  it("explains an unpublished release without exposing the raw HTTP response", () => {
    const updater = new AppUpdater();
    updaterMock.emit("error", new Error('Cannot find channel: HttpError: 404 GET https://example.com/latest-mac.yml'));
    expect(updater.snapshot().message).toBe("Обновления пока не опубликованы");
  });

  it("does not expose response details for unknown update failures", () => {
    const updater = new AppUpdater();
    updaterMock.emit("error", new Error("Invalid response with private diagnostic details"));
    expect(updater.snapshot().message).toBe("Не удалось выполнить обновление. Повторите попытку позже.");
  });

  it("requires explicit download and prepares the app before installation", async () => {
    const updater = new AppUpdater();
    expect(updaterMock.autoUpdater.autoDownload).toBe(false);
    expect(updaterMock.autoUpdater.autoInstallOnAppQuit).toBe(false);
    expect(updaterMock.autoUpdater.setFeedURL).not.toHaveBeenCalled();

    const info = { version: "1.2.8", files: [{ url: "LevikVPN-macOS-1.2.8-arm64.zip", sha512: "checksum" }] };
    updaterMock.emit("update-available", info);
    expect(updater.snapshot()).toEqual(expect.objectContaining({ status: "available", version: "1.2.8" }));

    updaterMock.autoUpdater.downloadUpdate.mockImplementationOnce(async () => {
      updaterMock.emit("download-progress", { percent: 47 });
      updaterMock.emit("update-downloaded", info);
      return ["/tmp/LevikVPN-macOS-1.2.8-arm64.zip"];
    });
    await updater.download();
    expect(updater.snapshot()).toEqual(expect.objectContaining({ status: "downloaded", progress: 100 }));
    expect(installerMock.verifyDownloadedUpdate).toHaveBeenCalledWith(["/tmp/LevikVPN-macOS-1.2.8-arm64.zip"], info);

    const prepare = vi.fn(async () => undefined);
    const beforeQuit = vi.fn();
    await updater.install(prepare, beforeQuit);
    expect(prepare).toHaveBeenCalledOnce();
    expect(installerMock.prepareMacUpdate).toHaveBeenCalledOnce();
    expect(installerMock.launchMacUpdateInstaller).toHaveBeenCalledOnce();
    expect(beforeQuit).toHaveBeenCalledOnce();
    expect(appMock.quit).toHaveBeenCalledOnce();
  });

  it("does not offer a downloaded archive that fails manifest verification", async () => {
    const updater = new AppUpdater();
    updaterMock.emit("update-available", { version: "1.2.8", files: [] });
    installerMock.verifyDownloadedUpdate.mockRejectedValueOnce(new Error("Контрольная сумма обновления не совпадает"));
    await expect(updater.download()).rejects.toThrow("Контрольная сумма");
    expect(updater.snapshot()).toEqual(expect.objectContaining({ status: "error", progress: null }));
  });

  it("cleans staging when the privileged installer cannot be started", async () => {
    const updater = new AppUpdater();
    updaterMock.emit("update-available", { version: "1.2.8", files: [] });
    await updater.download();
    installerMock.launchMacUpdateInstaller.mockRejectedValueOnce(new Error("authorization cancelled"));
    await expect(updater.install(async () => undefined, vi.fn())).rejects.toThrow("authorization cancelled");
    expect(installerMock.cleanupPreparedMacUpdate).toHaveBeenCalledOnce();
    expect(appMock.quit).not.toHaveBeenCalled();
  });
});
