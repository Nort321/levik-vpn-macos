import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const arch = process.env.LEVIK_BUILD_ARCH ?? process.arch;
if (arch !== "arm64" && arch !== "x64") throw new Error("Unsupported macOS architecture");
const version = "1.14.4-lx.31";
const target = `darwin-${arch === "x64" ? "amd64" : arch}`;
const asset = `sing-box-${version}-${target}.tar.gz`;
const binary = "sing-box";
const pinned = {
  "arm64": "06dad88155c9cff2160348360c57b0387ded040ede2c2f9bffef38f96407184e",
  "x64": "c325b3c4c5abbcae9687efc32fc51c70d5599d46d1519d0f231cc981c860b587"
};
const directory = `vendor/trusttunnel/darwin-${arch}`;
const response = await fetch(
  `https://github.com/Leadaxe/sing-box-lx/releases/download/v${version}/${asset}`,
  { signal: AbortSignal.timeout(180_000) },
);
if (!response.ok) throw new Error(`TrustTunnel download failed: ${response.status}`);
const data = Buffer.from(await response.arrayBuffer());
if (createHash("sha256").update(data).digest("hex") !== pinned[arch]) {
  throw new Error("TrustTunnel helper checksum mismatch");
}

const temporary = await mkdtemp(join(tmpdir(), "levik-trusttunnel-"));
try {
  const archive = join(temporary, asset);
  await writeFile(archive, data);
  execFileSync("tar", ["-xf", archive, "-C", temporary]);
  const source = join(temporary, `sing-box-${version}-${target}`);
  await mkdir(directory, { recursive: true });
  await copyFile(join(source, binary), join(directory, binary));
  await copyFile(join(source, "LICENSE"), join(directory, "LICENSE"));
  await chmod(join(directory, binary), 0o755);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
