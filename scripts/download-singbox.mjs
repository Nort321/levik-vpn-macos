import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

// sing-box carries TUIC v5, which Xray does not implement. Assets are pinned by
// SHA-256 so a replaced upstream release cannot enter a signed build.
const arch = process.env.LEVIK_BUILD_ARCH ?? process.arch;
if (!['arm64', 'x64'].includes(arch)) throw new Error('Unsupported macOS architecture');
const version = '1.14.2';
const goArch = arch === 'arm64' ? 'arm64' : 'amd64';
const asset = `sing-box-${version}-darwin-${goArch}.tar.gz`;
const pinned = {
  arm64: '925c5382eca8492b0150f868a6db20b18290a38700e621724b3703fd453e032d',
  amd64: 'b0bfb0dc70a5fc708710b9f5ea98b9ee76d40fa4169928d25d73edc4331df2fe',
};
const directory = `vendor/singbox/darwin-${arch}`;

const response = await fetch(`https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset}`, { signal: AbortSignal.timeout(180_000) });
if (!response.ok) throw new Error(`sing-box download failed: ${response.status}`);
const bytes = Buffer.from(await response.arrayBuffer());
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (sha256 !== pinned[goArch]) throw new Error('sing-box SHA-256 verification failed');

const work = await mkdtemp(join(tmpdir(), 'levik-singbox-'));
try {
  await writeFile(join(work, asset), bytes);
  execFileSync('/usr/bin/tar', ['-xzf', join(work, asset), '-C', work]);
  await rm(directory, { recursive: true, force: true });
  await mkdir(directory, { recursive: true });
  const unpacked = join(work, `sing-box-${version}-darwin-${goArch}`);
  await rename(join(unpacked, 'sing-box'), join(directory, 'sing-box'));
  await rename(join(unpacked, 'LICENSE'), join(directory, 'LICENSE'));
  await chmod(join(directory, 'sing-box'), 0o755);
  await writeFile(join(directory, 'VERSION'), `v${version}\nSHA256 ${sha256}\n`);
} finally {
  await rm(work, { recursive: true, force: true });
}
console.info(`Verified ${asset}: ${sha256}`);
