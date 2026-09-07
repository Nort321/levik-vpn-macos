# Разработка и выпуск

## Сборка

Нужны macOS, Xcode Command Line Tools (`xcode-select --install`), Node.js 24 и npm.

```sh
npm ci
npm run download:xray
npm run lint
npm run build
npm test
npm run package:local
```

Артефакты находятся в `release/`. Для сборки под другую архитектуру задайте
`LEVIK_BUILD_ARCH=arm64` или `x64` и передайте соответствующий флаг electron-builder.
В CI каждая архитектура собирается и проверяется на своём runner.
Скрипт загрузки фиксирует Xray v26.7.28 и сверяет официальный SHA-256.

## Отдельный GitHub-репозиторий

Репозиторий: `Nort321/levik-vpn-macos`, на текущем этапе приватный.
Эта папка является его корнем; родительский каталог и другие приложения в него не входят.
Если имя репозитория отличается, поменяйте `build.publish[0].url` в `package.json`.
Секреты, локальные профили, `node_modules`, `vendor` и сборки исключены из Git.

Workflow `.github/workflows/macos-release.yml` проверяет PR и собирает обе
архитектуры. После успешных проверок push в `main` создаёт новую версию и GitHub Release.
Тег `vMAJOR.MINOR.PATCH` использует указанную версию.
Пока репозиторий приватный, скачивание релизов требует доступа к нему через GitHub;
встроенная проверка обновлений без GitHub-авторизации не получает эти релизы.
В релиз входят DMG, ZIP, единый `latest-mac.yml` для обеих архитектур и SHA256SUMS.

### Подпись Apple

Добавьте GitHub Actions secrets:

- `MAC_CSC_LINK`: сертификат Developer ID Application (.p12, base64).
- `MAC_CSC_KEY_PASSWORD`: пароль сертификата.
- `APPLE_ID`: Apple ID для нотариализации.
- `APPLE_APP_SPECIFIC_PASSWORD`: отдельный пароль приложения Apple.
- `APPLE_TEAM_ID`: идентификатор команды Apple Developer.

При наличии сертификата CI требует нотариализацию. Без сертификата создаётся
локально подписанная сборка для ручной установки. Приватные ключи не входят в исходники.

## Проверки

Порядок приёмочных проверок описан в [testing.md](testing.md).
Архитектура приложения — в [architecture.md](architecture.md).
