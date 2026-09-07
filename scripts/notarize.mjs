import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
export default async function notarize(context) {
  if (!process.env.APPLE_ID || !process.env.APPLE_APP_SPECIFIC_PASSWORD || !process.env.APPLE_TEAM_ID) {
    if (process.env.LEVIK_REQUIRE_NOTARIZATION === '1') throw new Error('Apple notarization credentials are required');
    console.info('Local build: Apple notarization is not configured.');
    return;
  }
  const path = join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
  const archive = `${path}.notarize.zip`;
  execFileSync('/usr/bin/ditto', ['-c', '-k', '--keepParent', path, archive]);
  // notarytool reads credentials from the environment-backed Keychain profile in CI.
  execFileSync('xcrun', ['notarytool', 'submit', archive, '--keychain-profile', 'levik-notary', '--wait'], { stdio: 'inherit' });
  execFileSync('xcrun', ['stapler', 'staple', path], { stdio: 'inherit' });
}
