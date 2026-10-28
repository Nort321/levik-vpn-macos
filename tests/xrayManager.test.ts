import { describe, expect, it, vi } from "vitest";
import { XrayManager, xrayConfigArguments } from "../src/main/vpn/xrayManager";

describe("Xray configuration channel", () => {
  it("validates explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(true)).toEqual([
      "run", "-test", "-format", "json", "-config", "stdin:",
    ]);
  });

  it("executes explicit JSON received only through stdin", () => {
    expect(xrayConfigArguments(false)).toEqual([
      "run", "-format", "json", "-config", "stdin:",
    ]);
  });

  it("keeps a running automatic core when only its control API is unavailable", async () => {
    const manager = new XrayManager();
    Reflect.set(manager, "running", true);
    const recheck = vi.fn(async () => {});
    Reflect.set(manager, "serviceRoutes", { smartAutoActive: true, refreshAutomatic: recheck });
    vi.spyOn(manager, "isHealthy").mockResolvedValue(false);
    const exit = vi.fn(), unhealthy = vi.fn(); manager.on("exit", exit); manager.on("unhealthy", unhealthy);
    const check = Reflect.get(manager, "checkTrafficHealth") as () => Promise<void>;
    for (let i = 0; i < 4; i++) await check.call(manager);
    expect(manager.isRunning()).toBe(true); expect(recheck).toHaveBeenCalledTimes(4);
    expect(exit).not.toHaveBeenCalled(); expect(unhealthy).not.toHaveBeenCalled();
  });
});
