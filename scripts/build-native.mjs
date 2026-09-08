import { execFileSync } from 'node:child_process';
import { mkdirSync, existsSync } from 'node:fs';

const arch = process.env.LEVIK_BUILD_ARCH ?? process.arch;
if (!['arm64', 'x64'].includes(arch)) throw new Error('Unsupported macOS architecture');
const output = `build/native/${arch}`;
mkdirSync(output, { recursive: true });
execFileSync('xcrun', ['swiftc', '-swift-version', '5', '-Osize', '-whole-module-optimization', '-Xlinker', '-dead_strip', '-target', `${arch === 'x64' ? 'x86_64' : arch}-apple-macos13.0`, '-module-cache-path', `${output}/module-cache`, 'native/Helper.swift', '-o', `${output}/levik-helper`, '-framework', 'SystemConfiguration', '-framework', 'Security'], { stdio: 'inherit' });
execFileSync(`${output}/levik-helper`, ['--self-test'], { stdio: 'inherit' });
if (!existsSync('build/icon.icns')) {
  mkdirSync('build/icon.iconset', { recursive: true });
  for (const size of [16, 32, 128, 256, 512]) {
    for (const scale of [1, 2]) {
      execFileSync('sips', ['-z', String(size * scale), String(size * scale), 'build/icon.png', '--out', `build/icon.iconset/icon_${size}x${size}${scale === 2 ? '@2x' : ''}.png`], { stdio: 'ignore' });
    }
  }
  execFileSync('iconutil', ['-c', 'icns', 'build/icon.iconset', '-o', 'build/icon.icns'], { stdio: 'inherit' });
}
