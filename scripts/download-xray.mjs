import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

const arch = process.env.LEVIK_BUILD_ARCH ?? process.arch;
if (!['arm64', 'x64'].includes(arch)) throw new Error('Unsupported macOS architecture');
const version = 'v26.7.28';
const asset = `Xray-macos-${arch === 'arm64' ? 'arm64-v8a' : '64'}.zip`;
const base = `https://github.com/XTLS/Xray-core/releases/download/${version}`;
const directory = `vendor/xray/darwin-${arch}`;
const archive = `vendor/xray/${asset}`;
await mkdir(directory, { recursive: true });
async function download(name) {
  const response = await fetch(`${base}/${name}`, { signal: AbortSignal.timeout(180_000) });
  if (!response.ok) throw new Error(`Xray download failed: ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}
const bytes = await download(asset);
const digest = (await download(`${asset}.dgst`)).toString('utf8');
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (!digest.toLowerCase().split(/\s+/).includes(sha256)) throw new Error('Xray SHA-256 verification failed');
await writeFile(archive, bytes);
execFileSync('/usr/bin/unzip', ['-oq', archive, '-d', directory]);
await chmod(`${directory}/xray`, 0o755);
await writeFile(`${directory}/VERSION`, `${version}\nSHA256 ${sha256}\n`);
await rm(archive);
console.info(`Verified ${asset} ${version}: ${sha256}`);
