import { createHash, timingSafeEqual } from "node:crypto";
import { execFile } from "node:child_process";
import { constants, createReadStream, promises as nodeFileSystemPromises } from "node:fs";
import { access, lstat, mkdir, mkdtemp, readFile, realpath, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, extname, join } from "node:path";
import { promisify } from "node:util";
import { app } from "electron";
import type { UpdateFileInfo, UpdateInfo } from "electron-updater";
import { ADMIN_LAUNCH_SCRIPT, quoteShellArgument } from "../macos/helperClient";

const execute = promisify(execFile);
const requireRuntimeModule = createRequire(__filename);
const APP_NAME = "Levik VPN.app";
const APP_IDENTIFIER = "com.leviknet.vpn.macos";
const INSTALLER_READY_TIMEOUT_MS = 180_000;
const INSTALLER_POLL_INTERVAL_MS = 100;

export interface DownloadedMacUpdate {
  archivePath: string;
  version: string;
  sha512: string;
}

export interface PreparedMacUpdate extends DownloadedMacUpdate {
  bundlePath: string;
  stagingRoot: string;
}

export async function verifyDownloadedUpdate(paths: string[], info: UpdateInfo): Promise<DownloadedMacUpdate> {
  if (!isReleaseVersion(info.version)) throw new Error("Некорректная версия обновления");
  const archivePath = paths.find((path) => extname(path).toLowerCase() === ".zip");
  if (!archivePath) throw new Error("Архив обновления не найден");
  const file = info.files.find((item) => updateFileName(item) === basename(archivePath));
  if (!file?.sha512) throw new Error("Manifest обновления не содержит контрольную сумму");
  const expected = Buffer.from(file.sha512, "base64");
  if (expected.length !== 64) throw new Error("Некорректная контрольная сумма обновления");
  const archive = await stat(archivePath);
  if (!archive.isFile() || archive.size <= 0) throw new Error("Архив обновления повреждён");
  if (file.size !== undefined && (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size !== archive.size)) {
    throw new Error("Размер архива обновления не совпадает с manifest");
  }
  const actual = await sha512File(archivePath);
  if (!timingSafeEqual(actual, expected)) throw new Error("Контрольная сумма обновления не совпадает");
  return { archivePath, version: info.version, sha512: file.sha512 };
}

export async function prepareMacUpdate(update: DownloadedMacUpdate): Promise<PreparedMacUpdate> {
  if (process.platform !== "darwin" || !app.isPackaged) throw new Error("Установка обновления доступна только в приложении macOS");
  const stagingDirectory = join(app.getPath("userData"), "update-staging");
  await mkdir(stagingDirectory, { recursive: true, mode: 0o700 });
  const stagingRoot = await mkdtemp(join(stagingDirectory, "install-"));
  try {
    await validateArchiveEntries(update.archivePath);
    await execute("/usr/bin/ditto", ["-x", "-k", update.archivePath, stagingRoot], { timeout: 300_000, maxBuffer: 1024 * 1024 });
    const bundlePath = join(stagingRoot, APP_NAME);
    const bundle = await lstat(bundlePath);
    if (!bundle.isDirectory() || bundle.isSymbolicLink()) throw new Error("Архив не содержит приложение Levik VPN");
    if (await realpath(bundlePath) !== bundlePath) throw new Error("Некорректный путь приложения в архиве");
    await execute("/usr/bin/codesign", ["--verify", "--deep", "--strict", bundlePath], { timeout: 120_000, maxBuffer: 1024 * 1024 });
    const identifier = await plistValue(bundlePath, "CFBundleIdentifier");
    const version = await plistValue(bundlePath, "CFBundleShortVersionString");
    if (identifier !== APP_IDENTIFIER || version !== update.version) throw new Error("Архив содержит другое приложение или версию");
    await access(join(bundlePath, "Contents", "MacOS", "Levik VPN"), constants.X_OK);
    return { ...update, bundlePath, stagingRoot };
  } catch (error) {
    try {
      await removeStagingRoot(stagingRoot);
    } catch (cleanupError) {
      console.error("Failed to clean rejected macOS update staging", cleanupError);
    }
    throw error;
  }
}

export async function launchMacUpdateInstaller(update: PreparedMacUpdate): Promise<void> {
  const executable = app.getPath("exe");
  if (!executable.startsWith("/Applications/") || !executable.includes(".app/Contents/MacOS/")) {
    throw new Error("Переместите Levik VPN в «Программы» и запустите оттуда");
  }
  const helper = join(process.resourcesPath, "native", "levik-helper");
  const readyPath = join(update.stagingRoot, ".installer-ready");
  const outputPath = join(update.stagingRoot, "installer.log");
  const argumentsList = [helper, "--install-update", String(process.pid), update.bundlePath, update.version, readyPath]
    .map(quoteShellArgument)
    .join(" ");
  const command = `/usr/bin/nohup ${argumentsList} >${quoteShellArgument(outputPath)} 2>&1 </dev/null &`;
  try {
    await execute("/usr/bin/osascript", ["-e", ADMIN_LAUNCH_SCRIPT, command], { timeout: 180_000, maxBuffer: 1024 * 1024 });
  } catch {
    throw new Error("Разрешение macOS не получено. Подтвердите установку обновления.");
  }
  const deadline = Date.now() + INSTALLER_READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const status = await readOptionalText(readyPath);
    if (status === "ready") return;
    if (status?.startsWith("error\n")) throw new Error(status.slice("error\n".length).trim() || "Системный установщик обновления завершился с ошибкой");
    const detail = await readOptionalText(outputPath);
    if (detail) throw new Error(detail);
    await new Promise((resolve) => setTimeout(resolve, INSTALLER_POLL_INTERVAL_MS));
  }
  const detail = await readOptionalText(outputPath);
  throw new Error(detail || "Системный установщик обновления не запустился");
}

export async function cleanupPreparedMacUpdate(update: PreparedMacUpdate): Promise<void> {
  await removeStagingRoot(update.stagingRoot);
}

async function readOptionalText(path: string): Promise<string | null> {
  try {
    return (await readFile(path, "utf8")).trim();
  } catch {
    return null;
  }
}

async function removeStagingRoot(stagingRoot: string): Promise<void> {
  const fileSystem = process.versions.electron
    ? (requireRuntimeModule("original-fs") as { promises: Pick<typeof nodeFileSystemPromises, "rm"> }).promises
    : nodeFileSystemPromises;
  await fileSystem.rm(stagingRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

function updateFileName(file: UpdateFileInfo): string | null {
  try {
    return basename(decodeURIComponent(new URL(file.url, "https://updates.invalid/").pathname));
  } catch {
    return null;
  }
}

async function sha512File(path: string): Promise<Buffer> {
  const hash = createHash("sha512");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest();
}

async function validateArchiveEntries(archivePath: string): Promise<void> {
  const { stdout } = await execute("/usr/bin/unzip", ["-Z1", archivePath], { encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
  const entries = stdout.split("\n").filter(Boolean);
  if (!entries.length || entries.length > 30_000) throw new Error("Некорректное содержимое архива обновления");
  for (const entry of entries) {
    if (!isSafeMacUpdateArchiveEntry(entry)) throw new Error("Архив обновления содержит небезопасный путь");
  }
}

export function isSafeMacUpdateArchiveEntry(entry: string): boolean {
  const parts = entry.split("/");
  return !entry.includes("\0")
    && !entry.startsWith("/")
    && !parts.some((part) => part === "." || part === "..")
    && parts[0] === APP_NAME;
}

async function plistValue(bundlePath: string, key: string): Promise<string> {
  const plist = join(bundlePath, "Contents", "Info.plist");
  const { stdout } = await execute("/usr/bin/plutil", ["-extract", key, "raw", "-o", "-", plist], { encoding: "utf8", timeout: 10_000 });
  return stdout.trim();
}

function isReleaseVersion(value: string): boolean {
  return /^\d+\.\d+\.\d+$/.test(value);
}
