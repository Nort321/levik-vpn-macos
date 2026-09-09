import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { UpdateInfo } from "electron-updater";
import { cleanupPreparedMacUpdate, isSafeMacUpdateArchiveEntry, launchMacUpdateInstaller, verifyDownloadedUpdate } from "../src/main/update/macUpdateInstaller";
import { ADMIN_LAUNCH_SCRIPT } from "../src/main/macos/helperClient";

vi.mock("electron", () => ({
  app: { getPath: () => "/Applications/Levik VPN.app/Contents/MacOS/Levik VPN" },
}));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  // A wrapper avoids copying execFile's custom promisify implementation,
  // which would bypass the mock and invoke the privileged AppleScript.
  return { ...actual, execFile: vi.fn((...args: Parameters<typeof actual.execFile>) => actual.execFile(...args)) };
});

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  vi.mocked(execFile).mockReset();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe.skipIf(process.platform !== "darwin")("macOS installer handoff", () => {
  async function setupInstaller(helperScript: string) {
    const directory = await mkdtemp(join(tmpdir(), "levik-installer-test-"));
    temporaryDirectories.push(directory);
    // Exercise quoting for executable, bundle, marker and log paths.
    const stagingRoot = join(directory, "user's $(literal) update");
    const resourcesPath = join(directory, "app's resources");
    await mkdir(stagingRoot);
    await mkdir(join(resourcesPath, "native"), { recursive: true });
    await writeFile(join(resourcesPath, "native", "levik-helper"), `#!/bin/sh\nset -eu\n${helperScript}\n`, { mode: 0o755 });
    vi.stubGlobal("process", Object.assign(Object.create(process) as NodeJS.Process, { resourcesPath }));
    const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
    vi.mocked(execFile).mockImplementation((file, args, options, callback) => {
      expect(file).toBe("/usr/bin/osascript");
      expect(args?.slice(0, 2)).toEqual(["-e", ADMIN_LAUNCH_SCRIPT]);
      // Run the production command through real AppleScript without prompting
      // for administrator privileges or touching the installed application.
      return actual.execFile(file, ["-e", "on run argv\n do shell script (item 1 of argv)\nend run", args![2]!], options, callback);
    });
    return {
      archivePath: join(directory, "update.zip"),
      version: "1.2.8",
      sha512: "checksum",
      bundlePath: join(stagingRoot, "Levik VPN.app"),
      stagingRoot,
    };
  }

  it("launches without a terminal and survives SIGHUP after the launching shell exits", async () => {
    const update = await setupInstaller([
      'test ! -t 0 && test ! -t 1 && test ! -t 2',
      // Wait for AppleScript to return before signalling the helper.
      'while [ ! -f "${5}.released" ]; do /bin/sleep 0.05; done',
      'kill -HUP "$$"',
      'printf "%s\\n" "$@" > "${5}.args"',
      'printf "ready\\n" > "$5"',
    ].join("\n"));
    const launch = launchMacUpdateInstaller(update);
    try {
      await vi.waitFor(() => expect(vi.mocked(execFile).mock.results[0]?.value.exitCode).toBe(0));
    } finally {
      await writeFile(join(update.stagingRoot, ".installer-ready.released"), "");
    }
    await expect(launch).resolves.toBeUndefined();
    expect(await readFile(join(update.stagingRoot, ".installer-ready.args"), "utf8")).toBe([
      "--install-update", String(process.pid), update.bundlePath, update.version, join(update.stagingRoot, ".installer-ready"), "",
    ].join("\n"));
    expect(await readFile(join(update.stagingRoot, "installer.log"), "utf8")).toBe("");
  });

  it("reports helper startup errors instead of waiting for readiness", async () => {
    const update = await setupInstaller('printf "installer failed\\n" >&2\nexit 1');
    await expect(launchMacUpdateInstaller(update)).rejects.toThrow("installer failed");
  });
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
