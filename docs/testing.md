# Release verification

Run `npm run lint`, `npm run build`, `npm test`, then build the installer.
`build` compiles the helper and runs native validation/firewall-generation tests.
Verify the bundle with `codesign --verify --deep --strict` and DMG with `hdiutil verify`.

Live acceptance on an installed app, using a test account:

1. Log in, reload account, change subscription and server; verify expired session handling.
2. Connect using a real server. Confirm changed public IPv4 and IPv6 behaviour using
   HTTPS requests, TCP downloads and a UDP service. A green UI alone is insufficient.
3. Check DNS with `scutil --dns` and packet capture on the physical interface.
   There must be no physical plaintext DNS to ISP resolvers with DNS guard enabled.
4. Exercise each routing mode and `.app/` inclusion/exclusion, including Chromium helpers.
5. Terminate only Levik's Xray child while connected. Confirm traffic stays blocked,
   reconnection succeeds and byte counts remain monotonic. Also test reconnect disabled.
6. Force-quit the UI. Verify no ordinary traffic escapes; reopen and explicitly disconnect.
7. Sleep/resume, switch Wi-Fi, lose network, disable/enable networking and reconnect.
8. Disconnect and quit. Verify normal DNS/network access and preservation of existing PF rules.
9. Reject the administrator prompt; retry. Test a second local user and duplicate app launch.
10. Test menu-bar actions, launch at login, all themes and all pages at 400×620 and 460×800.
11. Verify a signed update from a published test release before enabling public OTA.

Never run network fault-injection checks against another VPN process. Do not remove
unrelated firewall rules or reset the user's network configuration to make a test pass.

## Installed-app acceptance runner

After signing in and selecting a working server, quit Levik normally, then run:

```sh
"/Applications/Levik VPN.app/Contents/MacOS/Levik VPN" --release-checks
```

This is an explicit maintenance test: it changes routing and protection temporarily,
terminates only its own Xray core, and intentionally interrupts internet access.
Use an Ethernet/Wi-Fi uplink with other VPNs disconnected and allow the macOS
administrator prompt. It restores the original settings and reconnects at the end.
It must not be interrupted just because remote tooling loses connectivity.
For the narrower connectivity/DNS check use `--release-dns-checks` instead.
Do not launch a second instance while the normal application is still running.

Results are written to `~/Library/Application Support/levik-vpn-macos/diagnostics/`
as `release-checks.json` or `release-dns-checks.json`. Wait for `finished: true`
and inspect every result. The report contains outcomes, not account credentials,
profiles, public IP addresses or raw packet captures. DNS capture covers outbound
ports 53/853 on the active physical interface during the test window.

This runner covers executable routing using `/usr/bin/curl`; it does not substitute
for manually testing a complete `.app` and its helper processes. Sleep/wake, network
switching, UI force-quit, second-user authorization and signed OTA remain manual.
See [the 1.0.0 verification report](verification-1.0.0.md) for completed checks.
