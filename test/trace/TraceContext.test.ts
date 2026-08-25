import { describe, expect, it } from "vitest";
import { generateTraceContext, traceparent, TRACEPARENT_HEADER } from "../../src/trace/TraceContext.js";

describe("generateTraceContext", () => {
  it("gera traceId de 32 caracteres hexadecimais minúsculos", () => {
    const ctx = generateTraceContext();
    expect(ctx.traceId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("gera spanId de 16 caracteres hexadecimais minúsculos", () => {
    const ctx = generateTraceContext();
    expect(ctx.spanId).toMatch(/^[0-9a-f]{16}$/);
  });

  it("gera valores diferentes a cada chamada", () => {
    const a = generateTraceContext();
    const b = generateTraceContext();
    expect(a.traceId).not.toBe(b.traceId);
    expect(a.spanId).not.toBe(b.spanId);
  });

  it("o resultado é imutável", () => {
    expect(Object.isFrozen(generateTraceContext())).toBe(true);
  });
});

describe("traceparent", () => {
  it("monta o header no formato W3C (00-traceid-spanid-00)", () => {
    const ctx = { traceId: "a".repeat(32), spanId: "b".repeat(16) };
    expect(traceparent(ctx)).toBe(`00-${"a".repeat(32)}-${"b".repeat(16)}-00`);
  });

  it("TRACEPARENT_HEADER é o nome de header correto", () => {
    expect(TRACEPARENT_HEADER).toBe("traceparent");
  });
});
