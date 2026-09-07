# macOS architecture

## Boundaries

The Electron renderer is sandboxed with context isolation and no Node access.
The preload exposes the typed desktop API. The main process owns account requests,
RSA identity and profiles. Electron safeStorage uses macOS Keychain.

The native Swift helper runs only during an authorized application session. It is
launched with macOS administrator authorization, from the installed app bundle.
It validates the full signed bundle, checks the requesting executable and accepts
only the originating Electron main PID and UID over a root-owned Unix socket.
Root IPC accepts start, stop, protection, status and shutdown, plus fixed acceptance
operations: start/stop a physical DNS metadata audit, hash root PF rules, and abort
only the current owned Xray child. These operations use the same PID/UID checks. Executable
paths, shell commands and arbitrary file operations are never accepted.
The bundle seal is checked again before launching each core. Configuration file
references are rejected; privileged inbounds, routes, API and logging are fixed
by the helper. Runtime profiles are passed on stdin and never written in plaintext.

## Network lifecycle

Xray creates a free utun interface and expands IPv4/IPv6 `/0` configuration into
its Darwin protected routes. The helper selects the default outbound interface
before installing tunnel routes and pins Xray to it to avoid route recursion.
Before reporting connected, the helper requires a successful HTTPS response from
`https://1.1.1.1/cdn-cgi/trace` through a fixed loopback SOCKS inbound (127.0.0.1:47186)
that always routes through the selected VPN server. This checks the server transport;
it does not replace system routing, DNS/IPv6 leak and fault-injection acceptance tests.
On failure the core stops and the UI receives only known error categories. Raw
core log lines, destinations and credentials are not persisted or sent to the UI.
A root-created system group `_levikvpn`, with no members, identifies sockets of
the helper and Xray. Normal app/system sockets do not have this group.
PF allows those sockets and the current tunnel, loopback, DHCP and IPv6 neighbour
discovery, and blocks other outbound traffic while Kill Switch is active.
Existing states originating at physical interface IPs are cleared when connecting
so connections established before protection cannot bypass new rules.

Rules live only in `com.apple/000.levikvpn`; the helper verifies the system's
`com.apple/*` anchor and never overwrites `/etc/pf.conf` or other anchors.
PF enable references are acquired/released using tokens, preserving other users
of the firewall. The helper leaves a root-owned recovery marker on abnormal exit.
Kill Switch remains active after core/UI failure until intentional disconnect or
reboot. Restarting Levik VPN allows reconnect or removal after authorization.
The isolated system group remains after disconnect; it contains no user accounts.

The helper registers a session-owned supplemental DNS resolver for all domains
with SystemConfiguration. DNS requests from TUN are routed to Xray's DNS outbound,
and internal DNS traffic to the selected VPN server. DNS guard blocks physical
TCP/UDP 53/853, including core/helper sockets, before applying their broader allow rule.
Supplemental resolver state disappears
when its owner exits; permanent user network service preferences are not changed.
VPN endpoint hostnames bootstrap through Cloudflare HTTPS DNS at 1.1.1.1. Only
endpoint names are sent; ordinary DNS resolution follows the configured tunnel.

Statistics use the loopback Xray API. Main-process polling detects core failure.
Reconnect and resume preserve the firewall until the replacement tunnel is ready.
Intentional disconnect stops Xray, removes DNS and releases only Levik's PF rules.
The menu-bar Quit action completes cleanup before terminating the app.

## Distribution

Electron-builder bundles Xray and the native helper for the target architecture,
creates DMG/ZIP and signs nested binaries. Developer ID builds are notarized.
Local ad-hoc builds have a separate entitlement file for Electron's library loading.
Squirrel.Mac updates require Developer ID releases. CI publishes releases after
both architecture builds pass. Private repository assets require GitHub access;
local development scripts do not publish releases.
