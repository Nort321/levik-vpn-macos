import { app } from 'electron';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { connect, type Socket } from 'node:net';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const execute = promisify(execFile);
const SOCKET_PATH = '/var/run/levik-vpn/control.sock';
const MARKER_PATH = '/var/run/levik-vpn/protection.json';
export const ADMIN_LAUNCH_SCRIPT = 'on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run';
export type HelperStatus = { running: boolean; killSwitch: boolean; dnsProtection: boolean; pid: number | null; exitCode: number | null };

export function quoteShellArgument(value: string): string {
  if (value.includes('\0')) throw new Error('Invalid executable path');
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export class HelperClient {
  private socket: Socket | null = null;
  private starting: Promise<void> | null = null;
  private sequence = 0;
  private input = '';
  private pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  killSwitch = false;
  dnsProtection = false;

  get connected(): boolean { return this.socket !== null && !this.socket.destroyed; }

  async recoveredProtection(): Promise<boolean> {
    try {
      const marker: unknown = JSON.parse(await readFile(MARKER_PATH, 'utf8'));
      return isRecord(marker) && marker.killSwitch === true;
    } catch { return false; }
  }

  async request(command: string, data: Record<string, unknown> = {}): Promise<unknown> {
    if (!this.connected) {
      this.starting ??= this.launch().finally(() => { this.starting = null; });
      await this.starting;
    }
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('Системный VPN-помощник не ответил вовремя'));
      }, 60_000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket?.write(`${JSON.stringify({ id, command, ...data })}\n`, (error) => {
        if (error) this.close(error);
      });
    });
  }

  async status(): Promise<HelperStatus> {
    if (!this.connected) throw new Error("Связь с VPN-помощником потеряна");
    const value = await this.request('status');
    if (!isRecord(value) || typeof value.running !== 'boolean' || typeof value.killSwitch !== 'boolean' || typeof value.dnsProtection !== 'boolean') {
      throw new Error('Некорректный ответ VPN-помощника');
    }
    return { running: value.running, killSwitch: value.killSwitch, dnsProtection: value.dnsProtection, pid: typeof value.pid === 'number' ? value.pid : null, exitCode: typeof value.exitCode === 'number' ? value.exitCode : null };
  }

  async configure(): Promise<void> {
    if (!this.connected) return;
    await this.request('protection', { killSwitch: this.killSwitch, dnsProtection: this.dnsProtection });
  }

  async shutdown(): Promise<void> {
    if (this.connected) await this.request('shutdown');
    this.close(new Error('VPN-помощник остановлен'));
  }

  private async launch(): Promise<void> {
    if (process.platform !== 'darwin' || !app.isPackaged) throw new Error('Для VPN установите собранное macOS-приложение в «Программы»');
    if (!app.getPath('exe').startsWith('/Applications/')) throw new Error('Переместите Levik VPN в «Программы» и запустите оттуда');
    const executable = join(process.resourcesPath, 'native', 'levik-helper');
    const command = `${quoteShellArgument(executable)} --serve ${process.pid} >/dev/null 2>&1 &`;
    try {
      await execute('/usr/bin/osascript', ['-e', ADMIN_LAUNCH_SCRIPT, command], { timeout: 180_000 });
    } catch {
      throw new Error('Разрешение macOS не получено. Повторите подключение и подтвердите запрос администратора.');
    }
    let lastError: unknown;
    for (let attempt = 0; attempt < 100; attempt++) {
      try {
        await this.openSocket();
        return;
      } catch (error) { lastError = error; }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Не удалось запустить системный VPN-помощник${lastError instanceof Error && 'code' in lastError && lastError.code === 'EACCES' ? ': VPN занят другим пользователем Mac' : ''}`);
  }

  private openSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = connect(SOCKET_PATH);
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('Socket timeout')); }, 500);
      socket.once('error', (error) => { clearTimeout(timer); reject(error); });
      socket.once('connect', () => {
        clearTimeout(timer);
        this.socket = socket;
        this.input = '';
        socket.on('data', (chunk: Buffer) => this.receive(chunk));
        socket.on('error', () => this.close(new Error('Соединение с VPN-помощником прервано')));
        socket.on('close', () => { if (this.socket === socket) this.close(new Error('VPN-помощник завершил работу')); });
        resolve();
      });
    });
  }

  private receive(chunk: Buffer): void {
    this.input += chunk.toString('utf8');
    if (this.input.length > 1024 * 1024) { this.close(new Error('Слишком большой ответ VPN-помощника')); return; }
    let newline: number;
    while ((newline = this.input.indexOf('\n')) !== -1) {
      const line = this.input.slice(0, newline);
      this.input = this.input.slice(newline + 1);
      try {
        const message: unknown = JSON.parse(line);
        if (!isRecord(message) || typeof message.id !== 'number') throw new Error('Invalid helper message');
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        if (typeof message.error === 'string') pending.reject(new Error(message.error));
        else pending.resolve(message.result);
      } catch { this.close(new Error('Некорректный ответ VPN-помощника')); return; }
    }
  }

  private close(error: Error): void {
    const socket = this.socket;
    this.socket = null;
    socket?.destroy();
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.pending.clear();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export const macHelper = new HelperClient();
