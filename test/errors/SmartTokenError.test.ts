import { describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";

describe("SmartTokenError", () => {
  it("cria erro com mensagem", () => {
    const error = new SmartTokenError("Erro de teste");

    expect(error.message).toBe("Erro de teste");
    expect(error.cause).toBeUndefined();
  });

  it("cria erro com mensagem e causa", () => {
    const causa = new Error("causa original");
    const error = new SmartTokenError("Erro de teste", causa);

    expect(error.message).toBe("Erro de teste");
    expect(error.cause).toBe(causa);
  });

  it("é uma instância de Error", () => {
    const error = new SmartTokenError("Erro");

    expect(error).toBeInstanceOf(Error);
  });

  it("tem o nome da própria classe", () => {
    const error = new SmartTokenError("Erro");

    expect(error.name).toBe("SmartTokenError");
  });
});
