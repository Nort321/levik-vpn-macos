/** Public state only. The temporary access key never reaches snapshots or disk. */
export interface GuestSnapshot {
  name: string;
  expiresAt: number;
  phase: "connecting" | "connected" | "blocked" | "expired";
}

export const GUEST_CONNECTION_STEPS = [
  "На Android-телефоне включите Levik VPN, точку доступа и «Поделиться VPN → Через Levik».",
  "Подключите компьютер к Wi-Fi этого телефона. Оставьте телефон рядом и не выключайте раздачу.",
  "На телефоне скопируйте гостевое приглашение. Передайте его на этот компьютер лично или сохраните в текстовый файл.",
  "Вставьте приглашение ниже или выберите файл. Нажмите «Подключиться через телефон» и подтвердите системный запрос разрешения, если он появится.",
  "Дождитесь сообщения «Интернет через телефон». Аккаунт и отдельная подписка на компьютере не требуются.",
] as const;

export const GUEST_INVITE_WARNING = "Приглашение даёт временный доступ всем, у кого оно есть. Не публикуйте его. После завершения раздачи или срока доступа потребуется новое приглашение.";

export const GUEST_INVITE_MAX_LENGTH = 2_048;
