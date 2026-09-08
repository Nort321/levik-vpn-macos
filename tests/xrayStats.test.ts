import { describe, expect, it } from "vitest";
import { decodeQueryStatsResponse, encodeQueryStatsRequest, parseXrayStats } from "../src/main/vpn/xrayStats";

describe("Xray traffic statistics", () => {
  it("extracts TUN upload and download counters", () => {
    const result = parseXrayStats(JSON.stringify({
      stat: [
        { name: "inbound>>>levik-tun-in>>>traffic>>>uplink", value: "2048" },
        { name: "inbound>>>levik-tun-in>>>traffic>>>downlink", value: 8192 },
        { name: "outbound>>>levik-server>>>traffic>>>uplink", value: 999 },
      ],
    }));
    expect(result).toEqual({ uplink: 2048, downlink: 8192 });
  });

  it("ignores malformed and unrelated counters", () => {
    const result = parseXrayStats(JSON.stringify({
      stat: [
        { name: "inbound>>>levik-tun-in>>>traffic>>>uplink", value: "invalid" },
        { name: "inbound>>>levik-tun-in>>>traffic>>>downlink", value: -1 },
      ],
    }));
    expect(result).toEqual({ uplink: 0, downlink: 0 });
  });

  it("encodes the native QueryStats protobuf request", () => {
    expect(encodeQueryStatsRequest("tun").toString("hex")).toBe("0a0374756e");
  });

  it("decodes framed gRPC traffic counters without a CLI process", () => {
    const response = grpcFrame(Buffer.concat([
      protobufStat("inbound>>>levik-tun-in>>>traffic>>>uplink", 2_048),
      protobufStat("inbound>>>levik-tun-in>>>traffic>>>downlink", 8_192),
      protobufStat("outbound>>>levik-server>>>traffic>>>uplink", 999),
    ]));
    expect(decodeQueryStatsResponse(response)).toEqual({ uplink: 2_048, downlink: 8_192 });
  });

  it("rejects truncated or compressed gRPC messages", () => {
    expect(() => decodeQueryStatsResponse(Buffer.from([0, 0, 0, 0, 2, 1]))).toThrow("Truncated");
    expect(() => decodeQueryStatsResponse(Buffer.from([1, 0, 0, 0, 0]))).toThrow("Compressed");
  });
});

function protobufStat(name: string, value: number): Buffer {
  const nameBytes = Buffer.from(name);
  const stat = Buffer.concat([
    Buffer.from([0x0a]), varint(nameBytes.length), nameBytes,
    Buffer.from([0x10]), varint(value),
  ]);
  return Buffer.concat([Buffer.from([0x0a]), varint(stat.length), stat]);
}

function grpcFrame(message: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(message.length, 1);
  return Buffer.concat([header, message]);
}

function varint(value: number): Buffer {
  const bytes: number[] = [];
  do {
    let byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value > 0) byte |= 0x80;
    bytes.push(byte);
  } while (value > 0);
  return Buffer.from(bytes);
}
