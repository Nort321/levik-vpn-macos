# Changelog

## 1.1.0

- Добавили дополнительный способ подключения к серверам.
- Теперь способ подключения можно выбрать прямо в карточке сервера.
- Улучшили работу с обновлёнными настройками серверов в сетях с ограничениями.

## 1.0.1

- Enable Mux for the alternate VLESS XHTTP/SplitHTTP host to use server keepalives, preserving explicit profile settings and Anti-DPI behavior.
- Route Discord media and CDN domains through the VPN in blocked-only mode, including the bundled Discord geosite list.
- Keep sniffing limited to routing in generated configurations, matching the native helper and preserving destination IPs.
- Add regression tests and validate alternate XHTTP configurations with the native helper and bundled Xray core.

## 1.0.0

- First macOS client with the Windows visual style in a portrait window.
- Native utun, PF Kill Switch, DNS protection and application routing.
- Levik Account, server selection, statistics, settings and menu-bar controls.
- DMG/ZIP packaging and dual-architecture GitHub Actions builds.
- Fixed native validation rejecting the default DNS-over-HTTPS URL before tunnel startup.
- Added native validation of generated profiles with DoH enabled and disabled.
- Use Xray's Darwin protected routes and select the outbound interface before TUN startup.
- Require a successful HTTPS request through the selected VPN server before reporting connected.
- Classify core failures without persisting raw logs or exposing credentials.
- Apply protection before checking the tunnel when enabling Kill Switch during a session.
- Block physical DNS/DoT before the core/helper socket exemption.
- Add explicit installed-app acceptance checks for routing, DNS and core failure recovery.
- Exclude stale artifacts from update manifests and refuse CI uploads over published releases.
