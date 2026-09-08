import { EventEmitter } from "node:events";
import { app } from "electron";
import { autoUpdater } from "electron-updater";
import type { UpdateInfo } from "electron-updater";
import type { AppSnapshot } from "../../shared/contracts";
import {
  cleanupPreparedMacUpdate,
  launchMacUpdateInstaller,
  prepareMacUpdate,
  verifyDownloadedUpdate,
} from "./macUpdateInstaller";
import type { DownloadedMacUpdate, PreparedMacUpdate } from "./macUpdateInstaller";

type UpdateSnapshot = AppSnapshot["update"];

interface AppUpdaterEvents {
  changed: [snapshot: UpdateSnapshot];
}

export class AppUpdater extends EventEmitter<AppUpdaterEvents> {
  private state: UpdateSnapshot = { status: "idle", version: null, progress: null, message: null };
  private availableInfo: UpdateInfo | null = null;
  private downloadedUpdate: DownloadedMacUpdate | null = null;

  constructor() {
    super();
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowPrerelease = false;
    const updateUrlOverride = process.env.LEVIK_UPDATE_URL;
    if (updateUrlOverride) autoUpdater.setFeedURL({ provider: "generic", url: updateUrlOverride });
    autoUpdater.on("checking-for-update", () => this.patch({ status: "checking", message: "Проверяем обновления…" }));
    autoUpdater.on("update-available", (info) => {
      this.availableInfo = info;
      this.downloadedUpdate = null;
      this.patch({ status: "available", version: info.version, progress: 0, message: `Доступна версия ${info.version}` });
    });
    autoUpdater.on("update-not-available", () => {
      this.availableInfo = null;
      this.downloadedUpdate = null;
      this.patch({ status: "upToDate", version: app.getVersion(), progress: null, message: "Установлена актуальная версия" });
    });
    autoUpdater.on("download-progress", (progress) => this.patch({ status: "downloading", progress: Math.round(progress.percent), message: "Загрузка обновления…" }));
    autoUpdater.on("error", (error) => this.patch({ status: "error", progress: null, message: safeUpdateError(error) }));
  }

  snapshot(): UpdateSnapshot {
    return { ...this.state };
  }

  async check(silent = false): Promise<void> {
    if (!app.isPackaged) {
      if (!silent) this.patch({ status: "upToDate", version: app.getVersion(), progress: null, message: "Обновления проверяются только в установленной сборке" });
      return;
    }
    try {
      await autoUpdater.checkForUpdates();
    } catch (error) {
      if (!silent) this.patch({ status: "error", progress: null, message: safeUpdateError(error) });
    }
  }

  async download(): Promise<void> {
    const info = this.availableInfo;
    if (this.state.status !== "available" || !info) throw new Error("Сначала проверьте наличие обновления");
    this.patch({ status: "downloading", progress: 0, message: "Загрузка обновления…" });
    try {
      const paths = await autoUpdater.downloadUpdate();
      this.patch({ status: "downloading", progress: 100, message: "Проверка обновления…" });
      this.downloadedUpdate = await verifyDownloadedUpdate(paths, info);
      this.patch({ status: "downloaded", version: info.version, progress: 100, message: "Обновление готово к установке" });
    } catch (error) {
      this.downloadedUpdate = null;
      this.patch({ status: "error", progress: null, message: safeUpdateError(error) });
      throw error;
    }
  }

  async install(prepare: () => Promise<void>, beforeQuit: () => void): Promise<void> {
    const downloaded = this.downloadedUpdate;
    if (this.state.status !== "downloaded" || !downloaded) throw new Error("Обновление ещё не загружено");
    let preparedUpdate: PreparedMacUpdate | null = null;
    let handedOff = false;
    this.patch({ status: "installing", progress: 100, message: "Проверка приложения…" });
    try {
      preparedUpdate = await prepareMacUpdate(downloaded);
      this.patch({ status: "installing", progress: 100, message: "Подготовка к установке…" });
      await prepare();
      await launchMacUpdateInstaller(preparedUpdate);
      handedOff = true;
      beforeQuit();
      app.quit();
    } catch (error) {
      if (preparedUpdate && !handedOff) {
        try {
          await cleanupPreparedMacUpdate(preparedUpdate);
        } catch (cleanupError) {
          console.error("Failed to clean prepared macOS update staging", cleanupError);
        }
      }
      this.patch({ status: "downloaded", progress: 100, message: `Не удалось запустить установку: ${safeUpdateError(error)}` });
      throw error;
    }
  }

  private patch(patch: Partial<UpdateSnapshot>): void {
    this.state = { ...this.state, ...patch };
    this.emit("changed", this.snapshot());
  }
}

function safeUpdateError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/\b404\b|ERR_UPDATER_CHANNEL_FILE_NOT_FOUND/.test(message)) {
    return "Обновления пока не опубликованы";
  }
  if (/ENOTFOUND|ETIMEDOUT|ECONNREFUSED|ERR_INTERNET_DISCONNECTED|ERR_NETWORK_CHANGED/.test(message)) {
    return "Сервер обновлений недоступен. Повторите попытку позже.";
  }
  return "Не удалось выполнить обновление. Повторите попытку позже.";
}
