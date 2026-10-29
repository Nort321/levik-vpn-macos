import type { AppSnapshot } from "../shared/contracts";
import { GUEST_CONNECTION_STEPS, GUEST_INVITE_WARNING } from "../shared/sharing";

type Action = (operation: () => Promise<void>) => Promise<unknown> | void;

export function renderGuestScreen(root: HTMLElement, snapshot: Pick<AppSnapshot, "guest" | "busy" | "statusDetail">, platform: "macos" | "linux", run: Action, close: () => void): void {
  const guest = snapshot.guest;
  const busy = snapshot.busy;
  const expiry = guest ? new Date(guest.expiresAt).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "";
  const title = guest?.phase === "connected" ? "Интернет через телефон"
    : guest?.phase === "connecting" ? "Подключение к телефону…"
    : guest?.phase === "expired" ? "Время доступа закончилось"
    : guest ? "Соединение с телефоном прервано" : "Получить интернет от телефона";
  root.innerHTML = `<main class="login guest-page"><section class="card guest-card">
    <h1>${title}</h1>
    ${guest ? `<p>Телефон: <strong>${escape(guest.name)}</strong> · доступ до ${escape(expiry)}</p>
      <p role="status">${escape(snapshot.statusDetail ?? "")}</p>
      <p>${guest.phase === "connected" ? "Трафик этого подключения идёт через телефон владельца и его VPN. При потере связи автоматического перехода на обычный интернет не будет, пока работает системная защита Levik." : "Для повторного подключения проверьте Wi-Fi и раздачу телефона. Кнопка «Завершить гостевой режим» отключает гостевой туннель и снимает его сетевые ограничения."}</p>
      ${guest.phase === "blocked" ? `<button class="button primary" id="guest-retry" ${busy ? "disabled" : ""}>Повторить подключение</button>` : ""}
      <button class="button" id="guest-stop" ${busy ? "disabled" : ""}>Завершить гостевой режим</button>` : `
      <p>Подключитесь через Android-телефон с работающим Levik VPN. Root на телефоне не нужен.</p>
      <ol class="guest-steps">${GUEST_CONNECTION_STEPS.map((step) => `<li>${escape(step)}</li>`).join("")}</ol>
      <label class="guest-input-label" for="guest-invite">Гостевое приглашение</label>
      <textarea id="guest-invite" class="guest-invite" rows="3" maxlength="2200" spellcheck="false" autocomplete="off" placeholder="levik-share://v1/…" ${busy ? "disabled" : ""}></textarea>
      <p class="guest-hint">${GUEST_INVITE_WARNING}</p>
      <div class="guest-actions"><button class="button primary" id="guest-connect" ${busy ? "disabled" : ""}>Подключиться через телефон</button>
      <button class="button" id="guest-file" ${busy ? "disabled" : ""}>Выбрать файл приглашения</button>
      <button class="button" id="guest-back" ${busy ? "disabled" : ""}>Назад</button></div>`}
    <details class="guest-proxy-help"><summary>Подключиться без гостевого режима: настроить прокси вручную</summary>
      <p>Этот способ подходит браузеру и приложениям, которые поддерживают прокси. Он не защищает автоматически весь компьютер.</p>
      <ol class="guest-steps"><li>На телефоне выберите «Поделиться VPN → Без приложения», включите точку доступа и подключите компьютер к её Wi-Fi.</li>
      <li>Сохраните прежние настройки прокси или сделайте их снимок. Особенно важно сохранить адрес корпоративного прокси или PAC.</li>
      ${platform === "macos" ? `<li>Откройте  → Системные настройки → Сеть → Wi-Fi → Подробнее → Прокси.</li>
      <li>Включите «Веб-прокси (HTTP)» и «Защищённый веб-прокси (HTTPS)». В обоих разделах укажите сервер и порт, показанные телефоном. Сервер вводится без http://; порт — только цифры.</li>
      <li>Нажмите OK и примените изменения, если macOS предлагает это. Сертификаты устанавливать не нужно.</li>` : `<li>В GNOME откройте Настройки → Сеть → Сетевой прокси → Вручную. Названия пунктов в KDE и других окружениях отличаются.</li>
      <li>В полях HTTP-прокси и HTTPS-прокси укажите одинаковые сервер и порт с телефона. Сервер вводится без http://; порт — только цифры. Сохраните настройки.</li>
      <li>Если браузер не использует системный прокси, задайте эти параметры в его настройках сети. Поддержка зависит от браузера и окружения Linux.</li>`}
      <li>Откройте обычный сайт в браузере. Если телефон предлагает «Проверить подключение», выполните проверку. Проверка браузера не подтверждает маршрут других приложений.</li>
      <li>После завершения раздачи восстановите прежние настройки прокси. Если раньше прокси не было — отключите добавленные HTTP/HTTPS-прокси. Они могут продолжать действовать при смене Wi-Fi.</li></ol>
      <p>Не открывается страница: проверьте Wi-Fi, действующий адрес и порт телефона, работу VPN владельца. После перезапуска точки доступа адрес может измениться. Для игр и приложений, игнорирующих прокси, используйте гостевой режим Levik.</p>
    </details></section></main>`;
  root.querySelector<HTMLButtonElement>("#guest-back")?.addEventListener("click", close);
  root.querySelector<HTMLButtonElement>("#guest-retry")?.addEventListener("click", () => void run(() => window.levik.connect()));
  root.querySelector<HTMLButtonElement>("#guest-stop")?.addEventListener("click", () => void run(async () => { await window.levik.disconnectGuest(); close(); }));
  root.querySelector<HTMLButtonElement>("#guest-connect")?.addEventListener("click", () => {
    const input = root.querySelector<HTMLTextAreaElement>("#guest-invite");
    const invite = input?.value.trim() ?? "";
    if (!invite) { input?.focus(); return; }
    if (input) input.value = "";
    void run(() => window.levik.connectGuest(invite));
  });
  root.querySelector<HTMLButtonElement>("#guest-file")?.addEventListener("click", () => void run(() => window.levik.importGuestInvite()));
}

function escape(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character);
}
