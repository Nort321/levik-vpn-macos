// Codes from docs/connection-telemetry.md. Raw errors and log lines never
// leave the device; only these fixed identifiers do.

import type { AttemptStage } from "./sessionRecorder";

export type ProtocolName =
  | "vless-reality" | "vless-xhttp" | "vless-ws" | "vless-grpc" | "vless-tcp"
  | "hysteria2" | "tuic" | "trojan" | "shadowsocks" | "relay" | "yandex" | "other";

/** Health probe failure code for an error raised by a socket or TLS layer. */
export function probeErrorCode(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : "";
  switch (code) {
    case "ECONNREFUSED":
      return "refused";
    case "ECONNRESET":
    case "EPIPE":
    case "ECONNABORTED":
      return "reset";
    case "ETIMEDOUT":
      return "timeout";
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return "dns";
  }
  if (/^ERR_(TLS|SSL)|CERT|^UNABLE_TO_VERIFY|SELF_SIGNED/.test(code)) return "tls";
  return "other";
}

// The helper (native/Helper.swift) reduces core output to fixed categories
// and reports start failures with these messages; match them to codes.
const HANDSHAKE_DETAILS: ReadonlyArray<readonly [RegExp, string]> = [
  [/отклонил соединение/, "refused"],
  [/REALITY/, "reality_auth"],
  [/сертификат/i, "tls"],
  [/авторизации|отклонил профиль/, "auth_failed"],
  [/разрешить адрес|DNS/, "dns"],
  [/недоступна|Нет маршрута|исходящий сетевой интерфейс/, "unreachable"],
  [/не ответил вовремя/, "handshake_timeout"],
  [/закрыл соединение/, "reset"],
];

const START_FAILURES: ReadonlyArray<readonly [RegExp, AttemptStage, string]> = [
  [/Разрешение macOS не получено/, "tun", "permission_denied"],
  [/исходящий сетевой интерфейс/, "tun", "unreachable"],
  [/свободного VPN-интерфейса/, "tun", "tun_failed"],
  [/VPN-туннель не запустился|Ядро TUIC не запустилось|VPN-ядро не запущено/, "core", "core_start_failed"],
  [/Некорректн\S* (VPN-профиль|параметры TUIC|сертификат TUIC)|Не выбран VPN-сервер|адрес VPN-сервера/, "profile", "config_invalid"],
  [/помощник|Подпись приложения|Неизвестное приложение|Версия приложения|DNS|Программы|собранное macOS-приложение/i, "tun", "helper_failed"],
];

/** Stage and code of a failed tunnel start, or null when the message is not the helper's. */
export function helperStartFailure(message: string): readonly [AttemptStage, string] | null {
  if (message.includes("не передаёт данные")) {
    const detail = HANDSHAKE_DETAILS.find(([pattern]) => pattern.test(message));
    return detail ? ["handshake", detail[1]] : ["verify", "timeout"];
  }
  const failure = START_FAILURES.find(([pattern]) => pattern.test(message));
  return failure ? [failure[1], failure[2]] : null;
}

/**
 * macOS hardware port names ("Wi-Fi", "Ethernet Adapter (en4)",
 * "iPhone USB"). Tethering through a phone counts as cellular.
 */
export function networkTypeOfInterface(name: string | null): "wifi" | "cellular" | "ethernet" | "unknown" {
  if (!name) return "unknown";
  if (/wi-?fi|airport|wlan|wireless/i.test(name)) return "wifi";
  if (/iphone|ipad|bluetooth pan|cellular|mobile|wwan|lte|5g/i.test(name)) return "cellular";
  if (/ethernet|thunderbolt|\blan\b/i.test(name)) return "ethernet";
  return "unknown";
}

type ServerLike = { tuic?: unknown; outbound: Record<string, unknown> };

export function protocolOf(server: ServerLike): ProtocolName {
  if (server.tuic) return "tuic";
  const protocol = typeof server.outbound.protocol === "string" ? server.outbound.protocol.toLowerCase() : "";
  const stream = isRecord(server.outbound.streamSettings) ? server.outbound.streamSettings : {};
  const network = typeof stream.network === "string" ? stream.network.toLowerCase() : "tcp";
  const security = typeof stream.security === "string" ? stream.security.toLowerCase() : "none";
  switch (protocol) {
    case "vless":
      if (network === "xhttp" || network === "splithttp") return "vless-xhttp";
      if (network === "ws") return "vless-ws";
      if (network === "grpc") return "vless-grpc";
      return security === "reality" ? "vless-reality" : "vless-tcp";
    case "hysteria":
    case "hysteria2":
      return "hysteria2";
    case "tuic":
      return "tuic";
    case "trojan":
      return "trojan";
    case "shadowsocks":
      return "shadowsocks";
    default:
      return "other";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
