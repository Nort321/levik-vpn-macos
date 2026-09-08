import { app } from "electron";
import { macHelper } from "../macos/helperClient";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { XrayStatsClient } from "./xrayStats";

interface XrayEvents {
  log: [line: string];
  exit: [code: number | null, expected: boolean];
  stats: [downloadBytes: number, uploadBytes: number];
}

export class XrayManager extends EventEmitter<XrayEvents> {
  private running = false;
  private stopping = false;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  private statsQueryRunning = false;
  private statsErrorReported = false;
  private statsGeneration = 0;
  private readonly statsClient = new XrayStatsClient();

  async start(config: Record<string, unknown>): Promise<void> {
    this.stopping = true;
    this.stopStatsPolling();
    this.running = false;
    await macHelper.request("start", {
      config,
      killSwitch: macHelper.killSwitch,
      dnsProtection: macHelper.dnsProtection,
      dnsServer: dnsServerFromConfig(config),
    });
    this.running = true;
    this.stopping = false;
    this.startStatsPolling();
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.stopStatsPolling();
    if (macHelper.connected) await macHelper.request("stop");
    this.running = false;
  }

  isRunning(): boolean {
    return this.running;
  }

  async isHealthy(): Promise<boolean> {
    if (!this.running) return false;
    try {
      await this.statsClient.query("inbound>>>levik-tun-in>>>");
      return this.running;
    } catch {
      return false;
    }
  }

  executablePath(): string {
    return app.isPackaged
      ? join(process.resourcesPath, "xray", "xray")
      : join(app.getAppPath(), "vendor", "xray", `darwin-${process.arch}`, "xray");
  }

  private startStatsPolling(): void {
    this.stopStatsPolling();
    this.statsErrorReported = false;
    void this.queryStats();
    this.statsTimer = setInterval(() => void this.queryStats(), 2_000);
  }

  private stopStatsPolling(): void {
    if (this.statsTimer) clearInterval(this.statsTimer);
    this.statsTimer = null;
    this.statsGeneration += 1;
    this.statsQueryRunning = false;
    this.statsClient.close();
  }

  private async queryStats(): Promise<void> {
    if (!this.running || this.statsQueryRunning) return;
    this.statsQueryRunning = true;
    const generation = this.statsGeneration;
    try {
      const values = await this.statsClient.query("inbound>>>levik-tun-in>>>traffic>>>");
      if (generation !== this.statsGeneration) return;
      this.statsErrorReported = false;
      if (this.running) this.emit("stats", values.downlink, values.uplink);
    } catch (error) {
      if (generation !== this.statsGeneration) return;
      if (this.running) {
        if (!macHelper.connected) {
          this.running = false;
          this.stopStatsPolling();
          this.emit("exit", null, this.stopping);
          return;
        }
        const status = await macHelper.status().catch(() => null);
        if (status && !status.running) {
          this.running = false;
          this.stopStatsPolling();
          this.emit("exit", status.exitCode, this.stopping);
          return;
        }
      }
      if (!this.statsErrorReported && this.running) {
        this.statsErrorReported = true;
        this.emit("log", `Статистика Xray: ${error instanceof Error ? error.message : "ошибка запроса"}`);
      }
    } finally {
      if (generation === this.statsGeneration) this.statsQueryRunning = false;
    }
  }
}

export function xrayConfigArguments(validateOnly: boolean): string[] {
  return ["run", ...(validateOnly ? ["-test"] : []), "-format", "json", "-config", "stdin:"];
}

function dnsServerFromConfig(config: Record<string, unknown>): string {
  const dns = config.dns;
  if (typeof dns === "object" && dns !== null && "servers" in dns && Array.isArray(dns.servers)) {
    const server = dns.servers.find((item: unknown) => typeof item === "string" && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(item));
    if (typeof server === "string") return server;
  }
  return "1.1.1.1";
}
