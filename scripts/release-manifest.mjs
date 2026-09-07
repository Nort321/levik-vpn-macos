import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

const directory = process.argv[2] ?? 'release';
const version = process.argv[3] ?? JSON.parse(await readFile('package.json', 'utf8')).version;
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version');
const artifactPattern = new RegExp(`^LevikVPN-macOS-${version.replaceAll('.', '\\.')}-(arm64|x64)\\.(dmg|zip)$`);
const names = (await readdir(directory)).filter((name) => artifactPattern.test(name)).sort();
for (const arch of ['arm64', 'x64']) {
  const stem = `LevikVPN-macOS-${version}-${arch}`;
  if (names.includes(`${stem}.dmg`) !== names.includes(`${stem}.zip`)) throw new Error(`Incomplete ${arch} artifacts`);
}
const files = [];
const checksums = [];
for (const name of names) {
  const bytes = await readFile(join(directory, name));
  checksums.push(`${createHash('sha256').update(bytes).digest('hex')}  ${basename(name)}`);
  if (name.endsWith('.zip')) files.push({ url: name, sha512: createHash('sha512').update(bytes).digest('base64'), size: bytes.length });
}
if (!files.length) throw new Error('No update archives produced');
// JSON is valid YAML; both architectures belong in one MacUpdater manifest.
await writeFile(join(directory, 'latest-mac.yml'), JSON.stringify({ version, files, path: files[0].url, sha512: files[0].sha512, releaseDate: new Date().toISOString() }, null, 2) + '\n');
await writeFile(join(directory, 'SHA256SUMS.txt'), checksums.join('\n') + '\n');
