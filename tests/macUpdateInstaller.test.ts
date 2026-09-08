import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { UpdateInfo } from "electron-updater";
import { cleanupPreparedMacUpdate, isSafeMacUpdateArchiveEntry, verifyDownloadedUpdate } from "../src/main/update/macUpdateInstaller";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("custom macOS update verification", () => {
  it("accepts only paths contained by the expected application bundle", () => {
    expect(isSafeMacUpdateArchiveEntry("Levik VPN.app/Contents/MacOS/Levik VPN")).toBe(true);
    for (const entry of ["../Levik VPN.app/payload", "/Applications/Levik VPN.app", "Levik VPN.app/../payload", "Other.app/payload"]) {
      expect(isSafeMacUpdateArchiveEntry(entry)).toBe(false);
    }
  });

  it("accepts an archive only when its manifest size and SHA-512 match", async () => {
    const directory = await mkdtemp(join(tmpdir(), "levik-update-test-"));
    temporaryDirectories.push(directory);
    const archivePath = join(directory, "LevikVPN-macOS-1.2.8-arm64.zip");
    const contents = Buffer.from("verified update archive");
    await writeFile(archivePath, contents);
    const info = updateInfo("1.2.8", archivePath, contents);

    await expect(verifyDownloadedUpdate([archivePath], info)).resolves.toEqual({
      archivePath,
      version: "1.2.8",
      sha512: info.files[0]!.sha512,
    });
  });

  it("rejects a downloaded archive whose contents were changed", async () => {
    const directory = await mkdtemp(join(tmpdir(), "levik-update-test-"));
    temporaryDirectories.push(directory);
    const archivePath = join(directory, "LevikVPN-macOS-1.2.8-arm64.zip");
    const original = Buffer.from("original update archive");
    const info = updateInfo("1.2.8", archivePath, original);
    await writeFile(archivePath, Buffer.from("tampered update archive"));

    await expect(verifyDownloadedUpdate([archivePath], info)).rejects.toThrow(/размер|сумма/);
  });

  it("removes a prepared application bundle containing app.asar", async () => {
    const stagingRoot = await mkdtemp(join(tmpdir(), "levik-update-test-"));
    temporaryDirectories.push(stagingRoot);
    const resources = join(stagingRoot, "Levik VPN.app", "Contents", "Resources");
    await mkdir(resources, { recursive: true });
    await writeFile(join(resources, "app.asar"), "archive");

    await cleanupPreparedMacUpdate({
      archivePath: join(stagingRoot, "update.zip"),
      version: "1.2.8",
      sha512: "checksum",
      bundlePath: join(stagingRoot, "Levik VPN.app"),
      stagingRoot,
    });

    await expect(access(stagingRoot)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

function updateInfo(version: string, archivePath: string, contents: Buffer): UpdateInfo {
  return {
    version,
    files: [{
      url: archivePath.split("/").at(-1)!,
      sha512: createHash("sha512").update(contents).digest("base64"),
      size: contents.length,
    }],
    path: archivePath.split("/").at(-1)!,
    sha512: createHash("sha512").update(contents).digest("base64"),
    releaseDate: new Date(0).toISOString(),
  };
}
