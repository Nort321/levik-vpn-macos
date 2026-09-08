import { connect, constants, type ClientHttp2Session } from "node:http2";

export const XRAY_STATS_ENDPOINT = "127.0.0.1:47185";
const QUERY_STATS_PATH = "/xray.app.stats.command.StatsService/QueryStats";
const MAX_GRPC_RESPONSE_BYTES = 256 * 1024;

export type XrayTrafficStats = { uplink: number; downlink: number };

export class XrayStatsClient {
  private session: ClientHttp2Session | null = null;

  constructor(private readonly endpoint = XRAY_STATS_ENDPOINT) {}

  async query(pattern: string, timeoutMs = 3_500): Promise<XrayTrafficStats> {
    const session = this.getSession();
    const request = session.request({
      ":method": "POST",
      ":path": QUERY_STATS_PATH,
      "content-type": "application/grpc",
      "te": "trailers",
      "grpc-timeout": `${timeoutMs}m`,
    });
    const responseChunks: Buffer[] = [];
    let responseBytes = 0;
    let httpStatus = 0;
    let grpcStatus: string | undefined;
    let grpcMessage: string | undefined;

    return new Promise<XrayTrafficStats>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else {
          try {
            if (httpStatus !== 200) throw new Error(`Xray API returned HTTP ${httpStatus}`);
            if (grpcStatus !== undefined && grpcStatus !== "0") {
              throw new Error(`Xray API returned gRPC ${grpcStatus}${grpcMessage ? `: ${decodeURIComponent(grpcMessage)}` : ""}`);
            }
            resolve(decodeQueryStatsResponse(Buffer.concat(responseChunks, responseBytes)));
          } catch (decodeError) {
            reject(decodeError instanceof Error ? decodeError : new Error("Invalid Xray API response"));
          }
        }
      };
      const timer = setTimeout(() => {
        request.close(constants.NGHTTP2_CANCEL);
        finish(new Error("Xray API request timed out"));
      }, timeoutMs);

      request.on("response", (headers) => {
        httpStatus = typeof headers[":status"] === "number" ? headers[":status"] : 0;
        grpcStatus = headerValue(headers["grpc-status"]);
        grpcMessage = headerValue(headers["grpc-message"]);
      });
      request.on("trailers", (headers) => {
        grpcStatus = headerValue(headers["grpc-status"]) ?? grpcStatus;
        grpcMessage = headerValue(headers["grpc-message"]) ?? grpcMessage;
      });
      request.on("data", (chunk: Buffer) => {
        responseBytes += chunk.length;
        if (responseBytes > MAX_GRPC_RESPONSE_BYTES) {
          request.close(constants.NGHTTP2_CANCEL);
          finish(new Error("Xray API response is too large"));
          return;
        }
        responseChunks.push(chunk);
      });
      request.once("error", (error) => finish(error));
      request.once("end", () => finish());
      request.end(encodeGrpcFrame(encodeQueryStatsRequest(pattern)));
    });
  }

  close(): void {
    const session = this.session;
    this.session = null;
    session?.destroy();
  }

  private getSession(): ClientHttp2Session {
    if (this.session && !this.session.closed && !this.session.destroyed) return this.session;
    const session = connect(`http://${this.endpoint}`);
    session.unref();
    session.on("error", () => {
      if (this.session === session) this.session = null;
    });
    session.on("close", () => {
      if (this.session === session) this.session = null;
    });
    this.session = session;
    return session;
  }
}

export function parseXrayStats(raw: string): XrayTrafficStats {
  const value = JSON.parse(raw) as unknown;
  const stats = isRecord(value) && Array.isArray(value.stat) ? value.stat : [];
  let uplink = 0;
  let downlink = 0;
  for (const item of stats) {
    if (!isRecord(item) || typeof item.name !== "string") continue;
    const counter = typeof item.value === "number" ? item.value : Number(item.value ?? 0);
    if (!Number.isSafeInteger(counter) || counter < 0) continue;
    if (item.name === "inbound>>>levik-tun-in>>>traffic>>>uplink") uplink = counter;
    if (item.name === "inbound>>>levik-tun-in>>>traffic>>>downlink") downlink = counter;
  }
  return { uplink, downlink };
}

export function encodeQueryStatsRequest(pattern: string): Buffer {
  const value = Buffer.from(pattern, "utf8");
  return Buffer.concat([Buffer.from([0x0a]), encodeVarint(BigInt(value.length)), value]);
}

export function decodeQueryStatsResponse(raw: Buffer): XrayTrafficStats {
  let uplink = 0;
  let downlink = 0;
  let frameOffset = 0;
  while (frameOffset < raw.length) {
    if (frameOffset + 5 > raw.length) throw new Error("Truncated Xray API frame");
    if (raw[frameOffset] !== 0) throw new Error("Compressed Xray API responses are unsupported");
    const frameLength = raw.readUInt32BE(frameOffset + 1);
    frameOffset += 5;
    if (frameOffset + frameLength > raw.length) throw new Error("Truncated Xray API message");
    const message = raw.subarray(frameOffset, frameOffset + frameLength);
    frameOffset += frameLength;
    for (const stat of decodeStatsMessage(message)) {
      if (stat.name === "inbound>>>levik-tun-in>>>traffic>>>uplink") uplink = stat.value;
      if (stat.name === "inbound>>>levik-tun-in>>>traffic>>>downlink") downlink = stat.value;
    }
  }
  return { uplink, downlink };
}

function encodeGrpcFrame(message: Buffer): Buffer {
  const header = Buffer.allocUnsafe(5);
  header[0] = 0;
  header.writeUInt32BE(message.length, 1);
  return Buffer.concat([header, message]);
}

function decodeStatsMessage(message: Buffer): Array<{ name: string; value: number }> {
  const stats: Array<{ name: string; value: number }> = [];
  let offset = 0;
  while (offset < message.length) {
    const tag = decodeVarint(message, offset);
    offset = tag.offset;
    const field = Number(tag.value >> 3n);
    const wireType = Number(tag.value & 7n);
    if (field === 1 && wireType === 2) {
      const nested = readLengthDelimited(message, offset);
      offset = nested.offset;
      const stat = decodeStat(nested.value);
      if (stat) stats.push(stat);
    } else {
      offset = skipField(message, offset, wireType);
    }
  }
  return stats;
}

function decodeStat(message: Buffer): { name: string; value: number } | null {
  let name: string | null = null;
  let value: number | null = null;
  let offset = 0;
  while (offset < message.length) {
    const tag = decodeVarint(message, offset);
    offset = tag.offset;
    const field = Number(tag.value >> 3n);
    const wireType = Number(tag.value & 7n);
    if (field === 1 && wireType === 2) {
      const text = readLengthDelimited(message, offset);
      name = text.value.toString("utf8");
      offset = text.offset;
    } else if (field === 2 && wireType === 0) {
      const counter = decodeVarint(message, offset);
      offset = counter.offset;
      if (counter.value <= BigInt(Number.MAX_SAFE_INTEGER)) value = Number(counter.value);
    } else {
      offset = skipField(message, offset, wireType);
    }
  }
  return name !== null && value !== null ? { name, value } : null;
}

function encodeVarint(value: bigint): Buffer {
  const bytes: number[] = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0n);
  return Buffer.from(bytes);
}

function decodeVarint(buffer: Buffer, start: number): { value: bigint; offset: number } {
  let value = 0n;
  let shift = 0n;
  let offset = start;
  while (offset < buffer.length && shift <= 63n) {
    const byte = buffer[offset++];
    if (byte === undefined) break;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, offset };
    shift += 7n;
  }
  throw new Error("Invalid protobuf varint");
}

function readLengthDelimited(buffer: Buffer, start: number): { value: Buffer; offset: number } {
  const length = decodeVarint(buffer, start);
  if (length.value > BigInt(buffer.length)) throw new Error("Invalid protobuf length");
  const end = length.offset + Number(length.value);
  if (end > buffer.length) throw new Error("Truncated protobuf field");
  return { value: buffer.subarray(length.offset, end), offset: end };
}

function skipField(buffer: Buffer, offset: number, wireType: number): number {
  if (wireType === 0) return decodeVarint(buffer, offset).offset;
  if (wireType === 1) {
    if (offset + 8 > buffer.length) throw new Error("Truncated protobuf field");
    return offset + 8;
  }
  if (wireType === 2) return readLengthDelimited(buffer, offset).offset;
  if (wireType === 5) {
    if (offset + 4 > buffer.length) throw new Error("Truncated protobuf field");
    return offset + 4;
  }
  throw new Error(`Unsupported protobuf wire type ${wireType}`);
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
