import { app, BrowserWindow, dialog, Menu, nativeImage, powerMonitor, Tray } from "electron";
import { join } from "node:path";
import type { AppSnapshot, ConnectionStatus } from "../shared/contracts";
import { AppController } from "./appController";
import { registerIpc } from "./ipc";
import { runReleaseChecks } from "./releaseChecks";

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let controller: AppController | null = null;
let quitting = false;
let lastTrayKey = "";

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();

app.on("second-instance", () => showWindow());

app.whenReady().then(async () => {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: app.name, submenu: [{ role: "about" }, { type: "separator" }, { role: "hide" }, { role: "hideOthers" }, { role: "unhide" }, { type: "separator" }, { label: "Выйти из Levik VPN", accelerator: "Command+Q", click: requestQuit }] },
    { label: "Правка", submenu: [{ role: "undo" }, { role: "redo" }, { type: "separator" }, { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" }] },
    { label: "Окно", submenu: [{ role: "minimize" }, { label: "Открыть Levik VPN", click: showWindow }] },
  ]));
  controller = new AppController();
  mainWindow = createWindow();
  registerIpc(controller, mainWindow);
  controller.on("changed", updateTray);
  controller.on("updateInstalling", () => { quitting = true; });
  powerMonitor.on("resume", () => void controller?.restoreAfterSystemResume());
  powerMonitor.on("unlock-screen", () => void controller?.restoreAfterSystemResume());
  await controller.initialize();
  updateTray(controller.snapshot());
  mainWindow.show();
  if (process.argv.includes('--release-checks')) void runReleaseChecks(controller);
  else if (process.argv.includes('--release-dns-checks')) void runReleaseChecks(controller, true);
}).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error("Levik VPN startup failed", message);
  dialog.showErrorBox("Levik VPN не удалось запустить", message);
  app.quit();
});

app.on("activate", () => showWindow());

app.on("before-quit", (event) => {
  if (quitting || !controller) return;
  event.preventDefault();
  quitting = true;
  void controller.shutdown().finally(() => app.quit());
});

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({
    width: 460,
    height: 800,
    minWidth: 400,
    minHeight: 620,
    show: false,
    backgroundColor: "#07101f",
    title: "Levik VPN",
    icon: applicationIconPath(),
    autoHideMenuBar: true,
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 16, y: 18 },
    webPreferences: {
      preload: join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
    },
  });
  window.loadFile(join(__dirname, "..", "renderer", "index.html"));
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  window.on("close", (event) => {
    if (quitting) return;
    event.preventDefault();
    if (controller?.snapshot().settings.closeToTray ?? true) window.hide();
    else requestQuit();
  });
  window.on("show", refreshTrayMenu);
  window.on("hide", refreshTrayMenu);
  return window;
}

function createTray(): void {
  if (tray || controller?.snapshot().settings.showTrayIcon === false) return;
  const icon = trayIcon("disconnected");
  if (icon.isEmpty()) {
    console.error("Levik VPN tray icon is unavailable; continuing without tray");
    return;
  }
  tray = new Tray(icon);
  tray.setToolTip("Levik VPN — не подключено");
  tray.on("click", () => toggleWindow());
  updateTray(controller?.snapshot());
}

function updateTray(snapshot?: AppSnapshot): void {
  if (snapshot?.settings.showTrayIcon === false) {
    tray?.destroy();
    tray = null;
    lastTrayKey = "";
    return;
  }
  if (!tray) {
    createTray();
    return;
  }
  const status = snapshot?.status ?? "disconnected";
  const server = snapshot?.servers.find((item) => item.id === snapshot.selectedServerId);
  const key = `${status}\0${server?.id ?? ""}`;
  if (key === lastTrayKey) return;
  lastTrayKey = key;
  tray.setImage(trayIcon(status));
  const statusText = trayStatus(status);
  tray.setToolTip(`Levik VPN — ${statusText}${server ? ` · ${server.name}` : ""}`);
  const transitional = ["connecting", "reconnecting", "disconnecting"].includes(status);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: mainWindow?.isVisible() ? "Скрыть Levik VPN" : "Открыть Levik VPN", click: () => toggleWindow() },
    { type: "separator" },
    { label: "Подключить", enabled: !transitional && status !== "connected", click: () => void controller?.connect() },
    { label: "Отключить", enabled: !transitional && status === "connected", click: () => void controller?.disconnect() },
    { type: "separator" },
    { label: "Выход", click: requestQuit },
  ]));
}

function trayIcon(status: ConnectionStatus): Electron.NativeImage {
  const tone = status === "connected" ? "connected" : "disconnected";
  const statusIcon = nativeImage.createFromPath(join(__dirname, "..", "assets", `tray-${tone}.png`));
  if (!statusIcon.isEmpty()) {
    statusIcon.setTemplateImage(tone === "disconnected");
    return statusIcon;
  }
  return nativeImage.createFromPath(applicationIconPath()).resize({ width: 16, height: 16 });
}

function trayStatus(status: ConnectionStatus): string {
  return ({ disconnected: "не подключено", connecting: "подключение", connected: "подключено", reconnecting: "восстановление", disconnecting: "отключение", error: "ошибка" })[status];
}

function applicationIconPath(): string {
  return join(__dirname, "..", "assets", "icon.png");
}

function showWindow(): void {
  if (!mainWindow) return;
  mainWindow.show();
  mainWindow.focus();
}

function toggleWindow(): void {
  if (!mainWindow) return;
  if (mainWindow.isVisible()) mainWindow.hide();
  else showWindow();
}

function refreshTrayMenu(): void {
  lastTrayKey = "";
  updateTray(controller?.snapshot());
}

function requestQuit(): void {
  if (!quitting) app.quit();
}
