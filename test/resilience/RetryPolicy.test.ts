import { describe, expect, it } from "vitest";
import { computeRetryDelayMs } from "../../src/resilience/RetryPolicy.js";

describe("computeRetryDelayMs", () => {
  it.each([
    [1, 1000],
    [2, 2000],
    [3, 4000],
    [4, 8000],
  ])("tentativa %i produz delay de %ims", (attempt, expected) => {
    expect(computeRetryDelayMs(attempt)).toBe(expected);
  });
});
