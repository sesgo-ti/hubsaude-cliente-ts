import { describe, expect, it } from "vitest";
import {
  DEFAULT_ASSERTION_TTL_SECONDS,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_MAX_RETRIES,
  DEFAULT_REQUEST_TIMEOUT_MS,
  resolveFaultToleranceConfig,
} from "../../src/resilience/FaultToleranceConfig.js";

describe("resolveFaultToleranceConfig", () => {
  it("aplica todos os padrões quando nada é informado", () => {
    expect(resolveFaultToleranceConfig({})).toEqual({
      connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS,
      requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
      assertionTtlSeconds: DEFAULT_ASSERTION_TTL_SECONDS,
      maxRetries: DEFAULT_MAX_RETRIES,
    });
  });

  it("preserva valores explícitos válidos", () => {
    expect(
      resolveFaultToleranceConfig({
        connectTimeoutMs: 5000,
        requestTimeoutMs: 15000,
        assertionTtlSeconds: 120,
        maxRetries: 5,
      }),
    ).toEqual({
      connectTimeoutMs: 5000,
      requestTimeoutMs: 15000,
      assertionTtlSeconds: 120,
      maxRetries: 5,
    });
  });

  it.each([0, -1, -100])(
    "substitui assertionTtlSeconds=%i (não positivo) pelo padrão",
    (value) => {
      expect(resolveFaultToleranceConfig({ assertionTtlSeconds: value }).assertionTtlSeconds).toBe(
        DEFAULT_ASSERTION_TTL_SECONDS,
      );
    },
  );

  it.each([0, -1, -100])("substitui maxRetries=%i (não positivo) pelo padrão", (value) => {
    expect(resolveFaultToleranceConfig({ maxRetries: value }).maxRetries).toBe(DEFAULT_MAX_RETRIES);
  });

  it("o resultado é imutável (Object.freeze)", () => {
    const config = resolveFaultToleranceConfig({});
    expect(Object.isFrozen(config)).toBe(true);
  });
});
