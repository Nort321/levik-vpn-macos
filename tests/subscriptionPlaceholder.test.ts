import { describe, expect, it } from "vitest";
import { prepareTunnelProfile } from "../src/main/vpn/tunnelProfile";

const profile = (content: string) => Buffer.from(JSON.stringify({
  version: 1, profileId: "stub", subscriptionId: "sub", issuedAt: new Date().toISOString(),
  source: { mediaType: "text/plain", content },
}));
const stub = (remark: string) => `vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp#${encodeURIComponent(remark)}`;

describe("Remnawave stub links", () => {
  it("are never offered as servers", () => {
    expect(() => prepareTunnelProfile(profile(stub("Подписка закончилась · продлите в боте")), "sub"))
      .toThrow("Подписка закончилась · продлите в боте");
    expect(() => prepareTunnelProfile(profile(stub("Серверы временно недоступны")), "sub")).toThrow("нет серверов обычного VPN");
    const mixed = prepareTunnelProfile(profile(`${stub("Серверы временно недоступны")}\nvless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&type=tcp#DE`), "sub");
    expect(mixed.servers.map((server) => server.name)).toEqual(["DE"]);
  });
});
