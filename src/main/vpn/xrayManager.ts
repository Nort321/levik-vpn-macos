import { app } from "electron";
import { execFile } from "node:child_process";
import { macHelper } from "../macos/helperClient";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { parseXrayStats, XRAY_STATS_ENDPOINT } from "./xrayStats";

const execFileAsync = promisify(execFile);

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
      await execFileAsync(this.executablePath(), [
        "api", "statsquery", `--server=${XRAY_STATS_ENDPOINT}`, "-pattern", "inbound>>>levik-tun-in>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
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
    this.statsQueryRunning = false;
  }

  private async queryStats(): Promise<void> {
    if (!this.running || this.statsQueryRunning) return;
    this.statsQueryRunning = true;
    try {
      const status = await macHelper.status();
      if (!status.running) {
        this.running = false;
        this.stopStatsPolling();
        this.emit("exit", status.exitCode, this.stopping);
        return;
      }
      const { stdout } = await execFileAsync(this.executablePath(), [
        "api", "statsquery",
        `--server=${XRAY_STATS_ENDPOINT}`,
        "-pattern", "inbound>>>levik-tun-in>>>traffic>>>",
      ], { windowsHide: true, timeout: 3_500, maxBuffer: 256 * 1024 });
      const values = parseXrayStats(stdout);
      this.statsErrorReported = false;
      if (this.running) this.emit("stats", values.downlink, values.uplink);
    } catch (error) {
      if (!macHelper.connected && this.running) {
        this.running = false;
        this.stopStatsPolling();
        this.emit("exit", null, this.stopping);
      }
      if (!this.statsErrorReported && this.running) {
        this.statsErrorReported = true;
        this.emit("log", `Статистика Xray: ${error instanceof Error ? error.message : "ошибка запроса"}`);
      }
    } finally {
      this.statsQueryRunning = false;
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
